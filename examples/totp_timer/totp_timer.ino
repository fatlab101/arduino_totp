#include <sha1.h>
#include <totp.h>

#include "swRTC.h" //Must install Soft rtc
#include "Wire.h"

//create TOTP object
//The shared single secret expression is 'MyLegoDoor'
TOTP totp = TOTP("MyLegoDoor");
char totpCode[7]; //get 6 char code
long last_code=-1;
long counter=0;


swRTC rtc;

// TIMEZONE represents the number of hours offset from GMT
int TimeZone_Mins=10*60;

void setup() 
{
  Serial.begin(9600);
  if(!totp.save_secret_to_eeprom(32))
    Serial.println("failed to save secret to eeprom");
  //rtc.setup();
  //Set the RTC time automatically: Calibrate RTC time by your computer time
  //rtc.adjustRtc(F(__DATE__), F(__TIME__));
  
  //Adjust to match the current date and time - GMT timezone
  rtc.stopRTC(); 
  rtc.setDate(30, 11, 2021);
  rtc.setTime(11, 10, 0);
  rtc.startRTC(); 
}

void loop() 
{
  // put your main code here, to run repeatedly:  
  long GMT = rtc.getTimestamp();
  long code=totp.gen_code(GMT);
  if(code!=last_code) 
  {
    Serial.print("timestamp = ");
    Serial.print(GMT);
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

