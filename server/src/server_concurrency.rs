use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{Error,body::Body};
use actix_http::body::MessageBody;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::future::Future;

/// Middleware to control concurrent request processing.
/// This middleware wraps the entire application and allows only one request to be processed at a time.
pub struct ConcurrencyLimiter;

struct ConcurrencyLimiterMiddleware<S> {
    service: Arc<Mutex<S>>,
}

impl<S> Transform<S> for ConcurrencyLimiter
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<Body>, Error = Error> + 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<Body>;
    type Error = Error;
    type InitError = ();
    type Transform = ConcurrencyLimiterMiddleware<S>;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self::Transform, Self::InitError>>>>;

    fn new_transform(&self, service: S) -> Self::Future {
        // Wrap the service with our ConcurrencyLimiterMiddleware
        let middleware = ConcurrencyLimiterMiddleware {
            service: Arc::new(Mutex::new(service)),
        };
        Box::pin(async { Ok(middleware) })
    }
}

impl<S> Service for ConcurrencyLimiterMiddleware<S>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<Body>, Error = Error> + 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<Body>;
    type Error = Error;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.lock().unwrap().poll_ready(cx)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        // Ensure only one request is processed at a time by locking the mutex.
        let service = self.service.clone();
        Box::pin(async move {
            let mut lock = service.lock().unwrap();
            lock.call(req).await
        })
    }
}