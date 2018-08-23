// OpenAuthentication Time-based One-time Password Algorithm (RFC 6238)
// John Curtis

#ifndef _TOTP_H
#define _TOTP_H
#include "Arduino.h"
#include "sha1.h"

class TOTP 
{
private:
	static const int c_def_step_secs=30;	//default is 30 second steps
	static const int c_secret_buf=32;			//Should be adequate max buffer - allow a ~50 char expresssion
	static const long c_bad_code =-1; 
public:
	TOTP(int step_secs=c_def_step_secs):m_time_step_secs(step_secs),m_secret_len(0){}
	TOTP(const uint8_t* hmacKey,int keyLen,int step_secs=c_def_step_secs)
	:m_time_step_secs(step_secs),m_secret_len(0){update_secret(hmacKey,keyLen);}
	TOTP(const char* hmacKeyStr,int step_secs=c_def_step_secs)
	:m_time_step_secs(step_secs),m_secret_len(0){update_secret(hmacKeyStr);}
public:
	//Secret
	bool have_secret()const	{return m_secret_len>0;}
	//const uint8_t* secret()const{return m_secret;}
	//int secret_len()const		{return m_secret_len;}
	bool update_secret(const uint8_t* hmacKey,int keyLen)
		{
		m_secret_len=decode_32(m_secret,hmacKey,keyLen);	//base32 -> binary
		return m_secret_len>0;
		}
	bool update_secret(const char* hmacKeyStr)
		{
		return	hmacKeyStr!=NULL &&
						update_secret(reinterpret_cast<const uint8_t*>(hmacKeyStr),strlen(hmacKeyStr));
		}
	//Generate code
	long gen_code(long timeStamp){return gen_code_steps(timeStamp/m_time_step_secs);}
	//Update secret & generate code
	long gen_code(const uint8_t* hmacKey,int keyLen,long timeStamp)
		{
		return update_secret(hmacKey,keyLen) ? gen_code(timeStamp):c_bad_code;
		}
	long gen_code(const char* hmacKeyStr,long timeStamp)
		{
		return update_secret(hmacKeyStr) ? gen_code(timeStamp):c_bad_code;
		}
	//Date based equiv of above
	long gen_code(int year, int month, int day, int hour, int minute, int sec,int tz_mins=0)
		{
		return gen_code(to_timet(year,month,day,hour,minute,sec,tz_mins));
		}
	long gen_code(const uint8_t* hmacKey,int keyLen,
								int year, int month, int day, int hour, int minute, int sec,int tz_mins=0)
		{
		return gen_code(hmacKey,keyLen,to_timet(year,month,day,hour,minute,sec,tz_mins));
		}
	long gen_code(const char* hmacKeyStr,
								int year, int month, int day, int hour, int minute, int sec,int tz_mins=0)
		{
		return gen_code(hmacKeyStr,to_timet(year,month,day,hour,minute,sec,tz_mins));
		}
private:
	// Generate a code, using the number of steps provided
	long gen_code_steps(long steps)
		{
		if(!have_secret())
			return c_bad_code; //Not set!
		//map the number of steps in a 8-bytes array bigendian
		uint8_t challenge[8]={0,0,0,0,0,0,0,0};
		for(int i=1; i<=sizeof(long); steps>>=8, i++)
			challenge[8-i] = static_cast<uint8_t>(steps & 0XFF);
		//get the HMAC-SHA1 hash from counter and key
		sha1.init_hmac(m_secret,m_secret_len);
		sha1.write(challenge,8);
		const uint8_t* _hash= sha1.end_hmac();
		//apply dynamic truncation to obtain a 4-byte val
		const int offset=_hash[HASH_LENGTH-1] & 0x0F;
		long truncHash = 0;
		for(int i=0; i<4; i++) 
			{
			truncHash <<= 8;
			truncHash |= _hash[i+offset];
			}
		//compute the OTP value
		truncHash &= 0x7FFFFFFF;
		truncHash %= 1000000; //Trim to Six digits 0 -> 999999
		return truncHash;
		}	
private:
	int			m_time_step_secs;
	uint8_t m_secret[c_secret_buf];
	int			m_secret_len;
public:
	static bool code_to_str(long code,char s_code[7])
		{
		if(code==c_bad_code)
			sprintf(s_code,"error");
		int val=sprintf(s_code,"%06ld",code);// convert the value in string, with heading zeroes
		return val==6;
		}
	// Date to time_t unix time
	// Assume year is actual year
	// Assume months 1-12
	// Assume day 1-31
	// Assume hour 0-23
	// Assume min 0-59
	// Assume sec 0-59
	static long	to_timet(int year, int month, int day, int hour, int minute, int sec,int tz_mins=0)
		{
		const uint8_t days_per_month[]={31,28,31,30,31,30,31,31,30,31,30,31};
		const long sec_per_day=3600*24L;
		//Start with seconds from 1970 till 1 jan 00:00:00 this year
		long res= (year-1970)*(sec_per_day*365);
		//add extra days for leap years
		for(int i=1970; i<year; i++) 
			if((i%4)==0)
				res+=sec_per_day;  
		//add days for this year
		for(int i=1; i<=month; i++) 
			{
			if(month==2 && (year%4)==0)
				res+= sec_per_day*29;
			else 
				res+= sec_per_day*days_per_month[month-1];
			}  
		//add days this month
		res+=(day-1)*sec_per_day;
		//Add time today
		res+=hour*3600L+minute*60L+sec;
		//TZ minutes to get to UTC if needed
		res-=tz_mins*60L;  
		return res; 
		}
private:
	//decode secret from Base32 to a binary representation, and check that we
	//have at least one byte's worth of secret data.
	static int	decode_32(uint8_t secret[c_secret_buf],const uint8_t* in_buf,int in_len)
		{
		const int c_bits_per_char32=5;  //base32 binary 
		const int c_bits_per_byte=8;  
		if(in_buf==NULL || in_len<=0)
			return 0;
		// Sanity check
		// Estimated number of bytes needed to represent the decoded secret. Because
		// of white-space and separators, this is an upper bound needed
		const int poss_len_needed = (in_len+7)/8*c_bits_per_char32;
		if(poss_len_needed>c_secret_buf)
			return 0;
		int buffer=0;
		int bitsLeft=0;
		int count=0;
		for(int i=0; i<in_len; i++) 
			{
			uint8_t ch = in_buf[i];
			if(ch==' ' || ch=='\t' || ch=='\r' || ch=='\n' || ch=='-') //skip whitespace
				continue; //skip
			buffer<<=c_bits_per_char32;
			//Look up one base32 digit
			if((ch>='A' && ch<='Z') || (ch>='a' && ch<='z'))
				ch = (ch & 0x1F) - 1;
			else if (ch>='2' && ch<='7')
				ch -= '2'-26;
			else 
				return 0;
			buffer|=ch;
			bitsLeft+=c_bits_per_char32;
			if(bitsLeft>=c_bits_per_byte)
				{
				secret[count]=static_cast<uint8_t>(buffer >> (bitsLeft-c_bits_per_byte));
				count++;
				if(count>=c_secret_buf)
					return 0; //Overrun!
				bitsLeft-=c_bits_per_byte;
				}
			}
		return count;
		}
};

#endif