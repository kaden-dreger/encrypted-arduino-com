#include <Arduino.h>
#include <math.h>

// declaring global variables
const int randPin = 1;
const int P = 19211;

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
uint16_t privateKey() {
    // initializing local variables
    uint16_t privKey = 0;
    int LSB = 0, tempInt = 0, base2 = 2;
    // computing our private key
    for (int i = 0; i < 16; i++) {
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
    Serial.print("The private key: ");
    Serial.println(privKey);
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
uint32_t makeKey(int a, uint16_t b) {
    uint32_t result;  // Initializing the resulting key.
    /* A for loop that runs 'b' number of times*/
    for (uint16_t i = 0; i < b; i++) {
        if (i == 0) {
            result = 1 % P;  // Setting up the result.
            a = a % P;  // Setting up 'a'.
        }
        /* Performing the calculations of 'result' step-by-step*/
        result = (result * a) % P;
    }
    return result;
}


/*
    This function is a modified implementation from the version
    showed in class, specifically the diffie_hellman_prelim.cpp
*/
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
uint32_t publicKey(uint16_t privKey) {
    uint32_t pubKey = 0;  // Initializing the pubKey.
    int g = 6;  // Assigning the base as specified.
    /* Calling makeKey with 'g' and 'privKey' as parameters.*/
    pubKey = makeKey(g, privKey);
    Serial.print("Your public key: ");
    Serial.println(pubKey);
    return pubKey;
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


/*
    This function is a modified implementation from the version
    showed in class, specifically the diffie_hellman_prelim.cpp
*/
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
    return (static_cast<char> dLetter);
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
This function is responsible for setting up the arduino to be
able to communicate on both serial ports.
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*/
void setup() {
    init();    // Initializing the arduino.
    Serial.begin(9600);    // Setting up the serial ports.
    Serial3.begin(9600);
    Serial.println("Program is now running...");
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
This is the main function of the program and calls all other
functions from here. This is the high level algorithm for
our program.
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*/
int main() {
    uint16_t privKey, incomingKey;  // Initializing values.
    uint32_t sharedKey, pubKey;
    setup();  // Calling each subsequent function.
    privKey = privateKey();
    pubKey = publicKey(privKey);
    incomingKey = getsharedInput();
    sharedKey = shareKey(incomingKey, privKey);
    Serial.flush();
    chat(sharedKey);
    return 0;
}
