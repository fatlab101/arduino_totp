#include <sha1.h>
#include <totp.h>
#include "Wire.h"

//create TOTP object
//The shared single secret expression is 'MyLegoDoor'
TOTP totp = TOTP("MyLegoDoor");
char totpCode[7]; //get 6 char code
long last_code=-1;
long counter=0;
long timeVal=0;

void setup() 
{
  Serial.begin(9600);
  if(!totp.save_secret_to_eeprom(32))
    Serial.println("failed to save secret to eeprom");

	timeVal=totp.gen_code(2021,11,30,11,0,0);
}

void loop() 
{
  // put your main code here, to run repeatedly:  
  timeVal+=1;
	delay(1000);
  long code=totp.gen_code(timeVal);
  if(code!=last_code) 
  {
    Serial.print("timestamp = ");
    Serial.print(timeVal);
    Serial.print(", magic number = ");
    Serial.print(code);
    totp.code_to_str(code,totpCode);
    Serial.print(", magic number str = ");
    Serial.println(totpCode);
    last_code=code;
    counter++;
    if(counter%8)
      if(!totp.update_secret_from_eeprom(32))
        Serial.println("failed to load secret to eeprom");
  }
}
