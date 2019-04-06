# Encryped Arduino Communication
## Summary
This program establishes a secure connection between two Arduinos. Using client/server handshake protocol, it allows for the generation and exchange of private/public keys. Each character is encrypted and decrypted on each host devices respectively.
## Running Instructions
### Hardware Components:
* 2 Arduino Mega 2560 Boards
* 5 banana plug wires
* 2 brown band resistors
### Wiring Instructions:
Arduino 1 Pin TX3 <---> Arduino 2 Pin RX3

Arduino 2 Pin TX3 <---> Arduino 1 Pin RX3

Arduino 1 GND     <---> Arduino 2 GND

Resistor 1 <---> Breadboard of Arduino 1 <---> Arduino 1 Pin 13

Resistor 2 <---> Breadboard of Arduino 2 <---> Arduino 2 Pin 13

## How To Use
In order to run the program, make sure both Arduino boards are wired correctly and connected to their respective computers. Proceed to the project directory in your terminal window. Use the following command on each computer:
```bash
make upload && serial-mon
```
The program will be uploaded to each Arduino board, and the serial monitor will be displayed in each user's terminal window. The program will display your *unique* **public key**, following a typical handshake protocol. A **shared key** will be generated and displayed. You are now free to chat back and forth, with each character being encrypted on the fly.