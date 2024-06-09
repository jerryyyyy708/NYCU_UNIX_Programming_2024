# 312551086 Lab4
## Challenge 1: Race Condition
The global variable ``fortune`` might be modified in different thread, so the flag can be showed by sending both flag and R in short time.
## Challenge 2: Reentrant
``gethostbyname2`` use a global struct which will be modified after connection. Therefore, by connecting to a random server first and then connect to localhost, when the first connection failed and try to connect again, it will get localhost instead of original host.
