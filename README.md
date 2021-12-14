# horrors-log4shell

> A micro lab (playground?) for CVE-2021-44228 (log4j)

*Don't expect the full attack chain to work out of box*

## Requirements

### Kali Linux

    # apt install default-jdk gradle maven

### macOS

    % brew install openjdk gradle maven

## Installation

    % git clone https://github.com/tasooshi/horrors.git; cd horrors
    % python3 -m venv .venv
    % source .venv/bin/activate
    % python3 setup.py install

## Usage

## Step 1: Compiling payload

This is the payload that is going to be executed by the victim:

    $ javac Payload.java

*JDK used to compilation must be compatible with a vulnerable server. Recommended use JDK 1.7.*

## Step 2: Running the vulnerable application

Listens on `8080` by default and exposes two paths: `/` and `/endpoint`:

    $ cd Vulnerable; mvn spring-boot:run

## Step 3: Running the data collector service

This daemon collects data incoming from exploited machines and logs into a JSON file:

    (.venv) $ ./collector.py

## Step 4: Executing the attack:

Opens up several ports that get proxied to a single JNDI handler (`class JNDI(SocketService)`). Starts sending requests automatically:

    (.venv) $ ./attacker.py

Visit `http://127.0.0.1:8889/send-requests` to resend the requests.

## Check:

So, in the end you should have the following services running:

* Service collector.py at port `8888`
* Service attacker.py for static content and control at port `8889`
* Service attacker.py at ports `1389`, `1099`
* Vulnerable Java application at port `8080`
