/*
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
* Assignment 2 Part 1
* Rutvik Patel and Kaden Dreger
* ID: 1530012 and 1528632
* CCID: rutvik, kaden
* CMPUT 274 Fall 2018
*
* This program establishes a basic chat program, sending encrypted characters
  back and forth between the Arduinos, after calculating separate keys for each
  user and displaying to the serial monitor 
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*/

#include <Arduino.h>  // including the required libraries
#include <math.h>

// declaring global variables
const int randPin = 1;
const uint32_t P = 2147483647;
const int communicationPin = 13;
bool isServer = false;

using namespace std;


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
The privateKey function takes in no paramaters.
    Returns:
        privKey: a uin16_t type variable which stores the
                 computed private key.
This function is responsible for generating the private key that
is to be used by the user. It uses the analog pin as a source of
varying voltage and uses that to compute "random" values, taking
the LSB everytime and using it to calculate the private key.
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*/
uint32_t privateKey() {
    // initializing local variables
    uint32_t privKey = 0;
    int LSB = 0, tempInt = 0, base2 = 2;

    // computing our private key
    for (int i = 0; i < 32; i++) {
        tempInt = analogRead(randPin);  // reading the randPin
        /* 
        https://stackoverflow.com/questions/6647783/check-value-
        of-least-significant-bit-lsb-and-most-significant-bit-msb-in-c-c
        This method was found from user Armen Tsirunyan on July 11 2011.
        */
        LSB = tempInt & 1;  // finding the LSB
        privKey += LSB*(pow(base2, i));  // updating privKey using the LSB
        delay(50);  // delay to allows the voltage of randPin to fluctuate
    }
    return privKey;
}


/*
    This function is a modified implementation from the version
    showed in class, specifically the diffie_hellman_prelim.cpp
*/
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
The makeKey function takes the following paramaters:
        a: Which is the base of the exponent to be calculated.
        b: Which is the power of the exponent to be calculated.
    Returns:
        result: a uin32_t type variable which stores the
                computed key.
This function is responsible for generating keys by using the
equation: 'result = (a**b)%P'. However, due to overflow issues
a step by step approach is used to calculate parts of the
equation at a time thus preventing overflow.
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*/
uint32_t makeKey(uint32_t a, uint32_t b) {
    uint32_t result;  // Initializing the resulting key.
    uint32_t nextB = b;

    if (nextB == b) {
            result = 1 % P;  // Setting up the result.
            a = a % P;  // Setting up 'a'.
        }
    while (nextB > 0) {
        if (nextB & 1) {
            result = (result*a) % P;
        }
        a = (a*a) % P;
        nextB = (nextB >> 1);
    }

    return result;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
The publicKey function takes the following paramaters:
        privKey: Which is a uint16_t private key that was created
                 previously.
    Returns:
        pubKey: a uin32_t type variable which stores the
                computed public key.
This function is responsible for generating the public key that
is sent to the partner user inorder to generate a shared key.
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*/
uint32_t publicKey(uint32_t privKey) {
    uint32_t pubKey = 0;  // Initializing the pubKey.
    uint32_t g = 16807;  // Assigning the base as specified.

    /* Calling makeKey with 'g' and 'privKey' as parameters.*/
    pubKey = makeKey(g, privKey);

    Serial.print("Your public key: ");
    Serial.println(pubKey);
    return pubKey;
}

void uint32_to_serial3(uint32_t num) {
  Serial3.write((char) (num >> 0));
  Serial3.write((char) (num >> 8));
  Serial3.write((char) (num >> 16));
  Serial3.write((char) (num >> 24));
}


/** Reads an uint32_t from Serial3, starting from the least-significant
 * and finishing with the most significant byte. 
 */
uint32_t uint32_from_serial3() {
  uint32_t num = 0;
  num = num | ((uint32_t) Serial3.read()) << 0;
  num = num | ((uint32_t) Serial3.read()) << 8;
  num = num | ((uint32_t) Serial3.read()) << 16;
  num = num | ((uint32_t) Serial3.read()) << 24;
  return num;
}


/** Waits for a certain number of bytes on Serial3 or timeout 
 * @param nbytes: the number of bytes we want
 * @param timeout: timeout period (ms); specifying a negative number
 *                turns off timeouts (the function waits indefinitely
 *                if timeouts are turned off).
 * @return True if the required number of bytes have arrived.
 */
bool wait_on_serial3( uint8_t nbytes, long timeout ) {
  unsigned long deadline = millis() + timeout;//wraparound not a problem
  while (Serial3.available()<nbytes && (timeout<0 || millis()<deadline)) 
  {
    delay(1); // be nice, no busy loop
  }
  return Serial3.available()>=nbytes;
}

uint32_t handshake(uint32_t key) {
    uint32_t otherKey;
    bool timeout = false;
    if (isServer) {
        while (true) {
            while (Serial3.available() == 0) {}  // waits for client
            if (wait_on_serial3(5, 1000) == false) {
                continue;
            }
            char message = Serial3.read();
            otherKey = uint32_from_serial3();
            if (message == 'C') {
                Serial3.write('A');
                uint32_to_serial3(key);
            }
            //while (Serial3.available == 0) {}
            if (wait_on_serial3(1, 1000) == false) {
                continue;
            }
            char tempChar = Serial3.read();
            while (tempChar != 'A') {
                //while(Serial3.available == 0) {}
                if (wait_on_serial3(4, 1000) == false) {
                    timeout = true;
                    break;
                }
                otherKey = uint32_from_serial3();
                if (wait_on_serial3(1, 1000) == false){
                    timeout = true;
                    break;
                }
                tempChar = Serial3.read();
            }
            if (timeout == true) {
                timeout = false;
                continue;
            }
            Serial.println("Server side ran successfully.");
            break;
        }
        Serial.println("Handshake success!");

    } else {
        while (true) {
            Serial3.write('C');
            uint32_to_serial3(key);
            if (wait_on_serial3(5, 1000) == false) {
                continue;
            }
            Serial.println("Client side ran successfully.");
            break;
        }
        char message = Serial3.read();
        otherKey = uint32_from_serial3();
        Serial3.write('A');
        Serial.println("Handshake success!");
    }
    return otherKey;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
The getsharedInput function takes no paramaters.

    Returns:
        inputRead: a uin16_t type variable which stores the
                   public key from the other user.
This function is responsible for getting the public key from
the other user. This is done by entering the key via keyboard
and reading it from serial-mon. Once the key is read it is
returned as an integer.
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*/

uint16_t getsharedInput() {
    /* Initialization of the inputRead variable.*/
    uint16_t inputRead = 0;
    Serial.print("Enter your partner's key: ");

    while (true) {   // A while loop that runs until the return
                     // key is pressed.
        while (Serial.available() == 0) {}  // wait for input...
        /* Reading in the input as a character.*/
        char tempChar = Serial.read();

        /*https://stackoverflow.com/questions/5029840/
        convert-char-to-int-in-c-and-c*/
        /* Converting the ascii value to an integer.*/
        int tempInt = tempChar - '0';

        /* As each character is typed it is printed to the 
           serial-mon.*/
        Serial.print(tempChar);

        /* This checks if the return key was pressed.*/
        if (tempChar == '\r') {
            break;

        } else {
            /* This makes sure that the entered input is 
               converted to a decimal integer by increasing
               the inputRead by 10 everytime a new char is
               read in.*/
            inputRead = inputRead*10 + tempInt;
        }
    }
    Serial.println();
    return inputRead;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
The shareKey function takes the following paramaters:
        input: Which is a uint16_t that is the other users key.
      privKey: Which is a uint16_t private key that was created
               previously.
      Returns:
        sharedKey: a uin32_t type variable which stores the
                   computed shared key.
This function is responsible for generating the shared key that
both users use to encrypt and decrpyt the messages sent.
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*/
uint32_t shareKey(uint16_t input, uint16_t privKey) {
    uint32_t sharedKey = 0;  // Initializing the sharedKey.

    /* Calling the makeKey function to create the sharedKey*/
    sharedKey = makeKey(input, privKey);

    Serial.print("The shared key is: ");
    Serial.println(sharedKey);  // Outputting the key.
    return sharedKey;
}


/*
    This function is a modified implementation from the version
    showed in class, specifically the encrypt_decrypt.cpp
*/
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
The encrypt function takes the following paramaters:
        letter: Is the character that needs to be encrypted.
        key: Which is the shared key used by both users.
    Returns:
        eLetter: This is an encrypted letter saved as a
                 uint8_t.
This function is responsible for encrypting a given character and
returning that letter encrypted as an uint8_t.
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*/
uint8_t encrypt(char letter, uint16_t key) {
    uint8_t key8 = (uint8_t) key;  // casting to a single byte
    uint8_t eLetter = ((uint8_t) letter) ^ key8;  // compute the encrypted char
    return eLetter;
}


/*
    This function is a modified implementation from the version
    showed in class, specifically the encrypt_decrypt.cpp
*/
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
The decrypt function takes the following paramaters:
        eLetter: This is an encrypted letter saved as a
                 uint8_t.
        key: Which is the shared key used by both users.
    Returns:
        letter: Which is the decrypted character.
This function is responsible for decrypting a given encrypted
letter and returning that decrypted character,
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*/
char decrypt(uint8_t eletter, uint16_t key) {
    uint8_t key8 = (uint8_t) key;  // casting to a single byte
    uint8_t dLetter = eletter ^ key8;  // computing the decrypted letter
    return (static_cast<char> (dLetter));
}


/*
    This function is a modified implementation from the version
    showed in class, specifically the encrypt_decrypt.cpp
*/
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
The chat function takes the following paramaters:
        key: Which is the shared key used by both users
             for encryption and decryption.
    Returns:
        This function does not return anything.
This function is the final step in the program as it will run
forever. The point of this function is to handle the
communication between each user. This is done by having two
more while loops embedded in the main while loop. The first
deals with sending information while the latter deals with
recieving info.
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*/
void chat(uint16_t key) {
    Serial.println("Chat is now running...");
    while (true) {  // Main while loop that never breaks.
        /* Wait for input from the user to send to the partner*/
        while (Serial.available() > 0) {
            /* Reads the input character by character*/
            char chatChar = Serial.read();

            /* Prints the typed characters to the screen.*/
            Serial.print(chatChar);

            if (chatChar == ('\r')) {   // If return is pressed
                /* Sends '\n' to the other user signaling the 
                end of the message*/
                Serial3.write(encrypt('\n', key));
                Serial.println();
                break;

            } else {
                /* Encrypt the given character then send to
                   serial3*/
                Serial3.write(encrypt(chatChar, key));
            }
        }

        /* Wait for input from partner to decode*/
        while (Serial3.available() > 0) {
            /* Read in the encrypted byte*/
            uint8_t byte = Serial3.read();

            /* Decrypt the given byte as a character*/
            char dByte = decrypt(byte, key);

            if (dByte == '\n') {    // Check for end of message.
                Serial.println();
                break;
            } else {
                /* Print the decrypted character to the serial moniter*/
                Serial.print(dByte);
            }
        }
    }
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
This function is responsible for setting up the Arduino to be
able to communicate on both serial ports.
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*/
void setup() {
    init();    // Initializing the arduino.
    Serial.begin(9600);    // Setting up the serial ports.
    Serial3.begin(9600);
    //Serial.println("Calculating key...");

    pinMode(communicationPin, INPUT);
    if (digitalRead(communicationPin) == HIGH){
        isServer = true;
    }
    if (isServer) {
        Serial.println("This is the server.");
    } else {
        Serial.println("This is the client.");
    }
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
This is the main function of the program and calls all other
functions from here. This is the high level algorithm for
our program.
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*/
int main() {
    uint32_t privKey, incomingKey;  // Initializing values.
    uint32_t sharedKey, pubKey, otherKey;

    setup();  // Calling each subsequent function.

    privKey = privateKey();
    pubKey = publicKey(privKey);
    //incomingKey = getsharedInput();
    //sharedKey = shareKey(incomingKey, privKey);
    otherKey = handshake(pubKey);
    Serial.print("The other key is: ");
    Serial.println(otherKey);

/* makes sure all the characters are pushed to the screen */
    Serial.flush();

    //chat(sharedKey);

    return 0;
}

