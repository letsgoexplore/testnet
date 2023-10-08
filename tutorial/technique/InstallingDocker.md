### Installing Docker
There are **Brief version**, where you can directly copy and paste in the terminal to install; and **Detailed 
### Brief

copy the code below to terminal

```rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sudo apt-get update
sudo apt-get install build-essential
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce
sudo systemctl start docker
sudo usermod -aG docker $USER
newgrp docker
```

### Detailed

Installation of Docker Engine usually involves running a series of commands on the operating system. Since different operating system versions may have differences, I will provide installation examples for three commonly used operating systems: Ubuntu (or other Debian-based Linux distributions), CentOS (or other RHEL-based Linux distributions), and Windows. For macOS, please install Docker Desktop.

1. Installing Docker Engine on Ubuntu:
    
    a. Update the package manager's package index:
    
    ```
    sudo apt-get update
    
    ```
    
    b. Install necessary dependencies to use repositories over HTTPS:
    
    ```
    sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common
    
    ```
    
    c. Add Docker's official GPG key:
    
    ```
    curl -fsSL <https://download.docker.com/linux/ubuntu/gpg> | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    
    ```
    
    d. Set up the stable Docker repository:
    
    ```
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] <https://download.docker.com/linux/ubuntu> $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    ```
    
    e. Install Docker Engine:
    
    ```
    sudo apt-get update
    sudo apt-get install -y docker-ce
    
    ```
    
    f. Start the Docker service:
    
    ```
    sudo systemctl start docker
    
    ```
    
    g. (Optional) Add the current user to the docker group to avoid using sudo every time Docker is used:
    
    ```
    sudo usermod -aG docker $USER
    
    ```
    
    Log out or restart the computer for the changes to take effect.
    

    h. After adding the user to the Docker group, you need to log out the current user and log in again, or execute the following command to apply the changes:

    ```
    newgrp docker

    ```

    or:

    ```
    su - $USER

    ```

    1. Now, your user should have been added to the Docker group, and you should be able to run Docker commands as a regular user without encountering permission issues.

    i. To verify if you have been successfully added to the Docker group, run the following command:

    ```
    docker info

    ```

    If it displays information about the Docker daemon without any permission errors, then you have successfully been added to the Docker group.

    Please note that for certain Linux distributions, the group used may be `docker` instead of `docker` user group. It might vary on specific distributions, but the above steps are a general solution.