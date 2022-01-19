# horrors-log4shell

> A micro lab (playground?) for CVE-2021-44228 (log4j)

* Can be used for executing payloads against multiple targets.
* Target-specific payloads are generated runtime.
* Adjustable configuration and bypasses.

## Installation

### Java-related requirements

* Development / Running example
    * Gradle
    * Maven
* In order to test the recent log4j related vulnerabilities (CVE-2021-44228, CVE-2021-45046):
    * JDK 8u121
    * Ysoserial compiled JAR (https://github.com/frohoff/ysoserial)
* Make sure to have compatible JDKs on both sides.

### Python requirements

    % pip3 install pyasn1 git+https://github.com/tasooshi/horrors

## Usage

### Step 1: Configuring

Copy and adjust the `attacker_config.py.example` configuration file.

### Step 2: Running the vulnerable application

Listens on `8080` by default and exposes two paths: `/` and `/endpoint`:

    $ cd Vulnerable; mvn spring-boot:run

### Step 3: Running the data collector service

This daemon collects data incoming from exploited machines and logs into a JSON file:

    (.venv) $ ./collector.py

### Step 4: Executing the attack:

Opens up several ports that get proxied to a single JNDI handler (`class JNDI(services.Service)`). Starts sending requests automatically:

    (.venv) $ ./attacker.py

Visit `http://127.0.0.1:8889/send-requests` to resend the requests.

### Check:

So, in the end you should have the following services running:

* `collector.py` at port `8888`
* `attacker.py` for static content and control at port `8889`
* `attacker.py` at ports `1389` and `8443`
* `Vulnerable.java` at port `8080`
