use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_service::ServiceFactory;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

/// Middleware to control concurrent request processing.
/// This middleware wraps the entire application and allows only one request to be processed at a time.
struct ConcurrencyLimiter;

impl<S, B> Transform<S> for ConcurrencyLimiter
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: actix_http::body::MessageBody,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type InitError = ();
    type Transform = ConcurrencyLimiterMiddleware<S>;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Transform, Self::InitError>>>>;

    fn new_transform(&self, service: S) -> Self::Future {
        // Wrap the service with our ConcurrencyLimiterMiddleware
        let middleware = ConcurrencyLimiterMiddleware {
            service: Arc::new(Mutex::new(service)),
        };
        Box::pin(async { Ok(middleware) })
    }
}

struct ConcurrencyLimiterMiddleware<S> {
    service: Arc<Mutex<S>>,
}

impl<S, B> Service for ConcurrencyLimiterMiddleware<S>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: actix_http::body::MessageBody,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.lock().unwrap().poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Ensure only one request is processed at a time by locking the mutex.
        let service = self.service.clone();
        Box::pin(async move {
            let lock = service.lock().unwrap();
            lock.call(req).await
        })
    }
}