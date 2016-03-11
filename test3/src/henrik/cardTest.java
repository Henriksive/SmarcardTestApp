package henrik;


import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.PIN;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.PublicKey;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;
import javacard.security.AESKey;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.*;
import javacard.security.*;

import java.lang.*;

public class cardTest extends Applet implements ExtendedLength{
	//Try to allocate all variable here and do not create new ones 
	//The Public/Private key pair that this card will use
	private KeyPair keys;
	//Signature object to sign with card private key
	private Signature sig;
	//Card Public key
	private RSAPublicKey k;
    //Card Private key
	private RSAPrivateKey k2;
    //TODO Local Certificate database for verification. Limit to xx certificates
	//private Certificate[]=new byte[10];
	
	//byte[] testSig = new byte[256];
	byte[] test = { 0x01, 0x02, 0x04, 0x05, 0x06, 0x07 };
    //	To store data to be sent beck to host application
	byte[] output = new byte[32767];
	//for temporary storing data before copying into output
	byte[] buff2 = new byte[2];
	//For bigger data
	byte[] bigArray;  
	//To store the size of the output buffer
	short size;
	//Length of signature or other short values
	short len;
	//Size of modulus and signature
	final short keysize=64;
	//PIN
	private OwnerPIN pin;
	//max_length of pin
	private final byte MAX_LENGTH=(byte) 0x04;
	//Max number of attempts
	private final byte MAX_ATTEMPTS=(byte) 0x05;
	
	//Predefined Commands
	private final byte CLA=(byte) 0x80;
	private final byte SEND_TEST_SIGNATURE=(byte) 0x00;
	private final byte SEND_PUB_MOD=(byte) 0x01;
	private final byte SEND_PUB_EXP=(byte) 0x02;
	private final byte SEND_PRV_EXP=(byte) 0x03;
	private final byte SEND_KEY_LENGTH=(byte) 0x04;
	//private final byte SIGN_INPUT_DATA=(byte) 0x05;
	//private final byte SEND_AUTHENTICATED_PUB_EXP=(byte) 0x06;
	
	//Cryptography
	Cipher cipherRSA;
	Cipher cipherAES;
	byte[] cryptoBuffer;// = new byte[32767];
	
	AESKey aesKey;
	RandomData randomData;
	byte[] rnd;
	
	short policy13Offset = 6;
	
	
	//Binding
	byte pinIsPresentFlag;
	OwnerPIN pincode;
	final byte PIN_TRY_LIMIT = 0x03;
	final byte PIN_SIZE = 0x04;
	final byte INCOMING_PIN_OFFSET = 0x00;
	byte[] h0Buffer = new byte[32767];
	//RSAPublicKey uPub;
	//RSAPublicKey mPub;
	
	
	
	
	//AESKey aesKey;
	private cardTest() {
		
		//Instantiate all object the applet will ever need
		//pin= new OwnerPIN(MAX_LENGTH, MAX_ATTEMPTS);
		//if(bArray==null){//check 
//			If no pin is passed as parameter at installation time use default 0000
			//pin.update(new byte[] {0x00,0x00,0x00,0x00}, (short) 0, (byte) 0x04);
		//	}
		//else {
			//pin.update(bArray, bOffset,  bLength);
		//}
		
		try{
			
			//Binding
			pinIsPresentFlag = 0x00;
			pincode = new OwnerPIN(PIN_TRY_LIMIT, PIN_SIZE);
			
			byte[] pincombination = {0x01, 0x03, 0x03, 0x07};
			pincode.update(pincombination, (short) 0, (byte) 0x04);
			
			
			
			
			keys = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_512);
			//keys = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
			
			//Set signature algorithm
			sig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
			//Generate the card keys
			keys.genKeyPair();
			//Get the public key
			k = (RSAPublicKey) keys.getPublic();
			//Get the private key
			k2 = (RSAPrivateKey) keys.getPrivate();
			//Initialize the signature object with card private key
			sig.init(k2, Signature.MODE_SIGN);
			
			//Crypto RSA
			cipherRSA = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
			
			//Crypto AES
			
			/*
			cipherAES = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
			aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
			randomData = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
			rnd = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_RESET);
			randomData.generateData(rnd, (short)0, (short)rnd.length);
			aesKey.setKey(rnd, (short) 0);
			*/
			//
		
			
			
			}catch(CryptoException ex){
			ISOException.throwIt((short)(ex.getReason()) );
			}catch(SecurityException ex){
			ISOException.throwIt((short)(0x6F10) );
			}catch(Exception ex){
			ISOException.throwIt((short)(0x6F20));
			}
		
			
			
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		
		new cardTest().register();//bArray, (short) (bOffset + 1), bArray[bOffset]);<-This was the reason it was giving error at installation time when creating the keys in the contructor....
	}

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}
		
		
		byte[] buff = apdu.getBuffer();
		output = new byte[32767];
		
		
		short dataOffset = (short) 7;

		 
		
		
		//Get the incoming APDU
		//Util.arrayCopy(apdu.getBuffer(),(short) 0, buff,(short) 0,(short) apdu.getBuffer().length);// apdu.getBuffer();
		//Check the CLA 
		
		/*
		if(buff[ISO7816.OFFSET_CLA]!=CLA){
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		*/
		//Switch on the instruction code INS
		switch (buff[ISO7816.OFFSET_INS]) {
//		Create a test signature using test
		case SEND_TEST_SIGNATURE: 	
			//Sign the test byte and get the signature size
			size = sig.sign(test, (short) 0, (short) test.length, output,
					(short) 0);
			break;
//			return modulus of public key	
		case SEND_PUB_MOD: 
			//Retrieve the modulus, store it in the output byte array and set the output length
			size = k.getModulus(output, (short) 0);
		    break;
//		  return exponent of public key  
		case SEND_PUB_EXP:  
//			Retrieve the public exponent, store it in the output byte array and set the output length
			size = k.getExponent(output, (short) 0);
			break;
//			return exponent of private key given correct pin authentication 
		case SEND_PRV_EXP: 
			// Check that the user is authenticated (correct command 0x80 0x03 0x01 0x00 0x04 0x00 0x00 0x00 0x00 0x00)
			if(buff[ISO7816.OFFSET_P1]==((byte) 0x01)){
				if(buff[ISO7816.OFFSET_LC]!=(byte) 0x00){
					if(pin.check(buff, (short) (ISO7816.OFFSET_LC+1), buff[ISO7816.OFFSET_LC])){
						size = k2.getExponent(output, (short) 0);
						pin.reset();
					} else {
						//wrong pin (system should have taken care of decrementing the counter and checking boundary conditions)
						ISOException.throwIt(ISO7816.SW_WRONG_DATA);
					}
				} else {
					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);//no pin was sent
				}
			} else {
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); //wrong command code	
			}
//			Retrieve the private exponent, store it in the output byte array and set the output length
			size = k2.getExponent(output, (short) 0);
			break;
//			return size of signature and modulus for testing purposes (they should be the same)
		case (byte) SEND_KEY_LENGTH: 
			shortToByteArray(keysize);
		    size=(short) 2;
		    Util.arrayCopy(buff, (short) 0, output, (short) 0, size);
			break;
			
		case (byte) 0x05:
			byte p1 = buff[ISO7816.OFFSET_P1];
		
			//First transaction
			if(p1 == (byte) 0x01){
				output[0] = 0x05; //Type of transaction
				if(pincode.isValidated()){
					output[1] = 0x01;
				}
				else{
					output[1] = 0x00;
				}
				output[2] = pincode.getTriesRemaining(); //PINIsOKFlag
				output[3] = 0x05;
				output[4] = 0x05;
				output[5] = 0x05;
				
				size = (short) 6;
			}
			
			//Second transaction
			else if(p1 == (byte) 0x02){
				//pincode.check(buff, (short) 7, PIN_SIZE); //TODO: DATAOFFSET
				output[0] = 0x05; //Type of transaction
				/*
				if(pincode.isValidated()){
					output[1] = 0x09;
					output[2] = 0x09;
					size = (short) 3;
					
				}
				else{
					output[1] = 0x00;
					output[2] = pincode.getTriesRemaining(); 
					size = (short) 3;
				}
				*/
				output[1] = 0x02;
				output[2] = 0x02;
				output[3] = 0x03;
				output[4] = 0x03;
				
				size = (short) 7;
				

			}
			
			else if(p1 == (byte) 0x03){
				if(pincode.isValidated()){
					
				}
				else{
					ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				}
				//mPub.setExponent(arg0, arg1, arg2)
				//aesKey.getKey(rnd, (short) 0);
			}
			
			
			
			break;
//			Sign arbitrary text sent to card
		/*case (byte) SIGN_INPUT_DATA: 
			size=(short) buff[ISO7816.OFFSET_LC];
		    size=sig.sign(buff,(short) (ISO7816.OFFSET_LC+1), size, output,
					(short) 0);
		    break;
//			return the modulus of public keywith a random value sent from the host
		*/
		    /*
		case (byte) SEND_AUTHENTICATED_PUB_EXP: 
			//Find the size of the random value
			size=(short) buff[ISO7816.OFFSET_LC];
		    //If the current key is 2048 bit =256 bytes we need a big array to store all data to sign
		    //TODO limit the size of the input value and do some checks on it 
		    bigArray=JCSystem.makeTransientByteArray((short) (size+keysize), JCSystem.CLEAR_ON_RESET);
		    //Update the signature object with that value
		    Util.arrayCopy(buff, (short) (ISO7816.OFFSET_LC+1), bigArray, (short) 0, size);
		    k.getModulus(bigArray, (short) (size));
		    //Util.arrayCopy(buff, (short) 0, bigArray, (short) (ISO7816.OFFSET_LC+size+1), len);
		    size = sig.sign(bigArray,(short) 0,(short) bigArray.length,output, (short) 0);
		    break;
		    */
		case (byte) 0x06:
			byte p1RSA = buff[ISO7816.OFFSET_P1];
			if(p1RSA == (byte) 0x01){
				cipherRSA.init(k, Cipher.MODE_ENCRYPT);
			}
			else if(p1RSA == (byte) 0x02){
				cipherRSA.init(k2, Cipher.MODE_DECRYPT);
			}
			
			
		
			short bytesReadRSA = apdu.setIncomingAndReceive();
			//size = bytesRead;
			size = apdu.getIncomingLength();
			short echoOffsetRSA = (short)0;
			while(bytesReadRSA > 0){
				Util.arrayCopyNonAtomic(buff, dataOffset, cryptoBuffer, echoOffsetRSA, bytesReadRSA);
				echoOffsetRSA += bytesReadRSA;
				bytesReadRSA = apdu.receiveBytes(dataOffset);
			}
			
			
			size = cipherRSA.doFinal(
		               cryptoBuffer, 
		               (short) 0,
		               size,
		               output,
		               (short)0);
			break;
		    
		case (byte) 0x07:
			
			
			break;
		case (byte) 0x08:	
			
			short bytesRead = apdu.setIncomingAndReceive();
			//size = bytesRead;
			size = apdu.getIncomingLength();
			short echoOffset = (short)0;
			while(bytesRead > 0){
				Util.arrayCopyNonAtomic(buff, dataOffset, output, echoOffset, bytesRead);
				echoOffset += bytesRead;
	            bytesRead = apdu.receiveBytes(dataOffset);
			}
			
			break;
			
		case (byte) 0x09:
			byte p1AES = buff[ISO7816.OFFSET_P1];
			if(p1AES == (byte) 0x01){
				cipherAES.init(aesKey, Cipher.MODE_ENCRYPT);
			}
			else if(p1AES == (byte) 0x02){
				cipherAES.init(aesKey, Cipher.MODE_DECRYPT);
			}
			
			
			short bytesReadECAES = apdu.setIncomingAndReceive();
			//size = bytesRead;
			size = apdu.getIncomingLength();
			short echoOffsetECAES = (short)0;
			while(bytesReadECAES > 0){
				Util.arrayCopyNonAtomic(buff, dataOffset, cryptoBuffer, echoOffsetECAES, bytesReadECAES);
				echoOffsetECAES += bytesReadECAES;
				bytesReadECAES = apdu.receiveBytes(dataOffset);
			}
			
			try{
			size = cipherAES.doFinal(
					cryptoBuffer, 
		               (short) 0,
		               (short) size,
		               output,
		               (short)0);
			}
			catch(CryptoException ex){
				size = 2;
				output[0] = (byte) ex.getReason();
				output[1] = 0x02;
			}
				
			break;
			
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
		
		send(apdu);
	}

	
	//Converts two adjacent bytes in a given array to a short 
	/*private static short readShort(byte[] data, short offset) {
		return (short) (((data[offset] << 8)) | ((data[offset + 1] & 0xff)));
	}*/
	
	//Convert a short value to a byte array and writes the result in the first two elements of buff
	private void shortToByteArray(short s) {

		buff2[0]=(byte) ((s & (short) 0xFF00) >> 8);
		buff2[1]=(byte) (s & (short) 0x00FF);
		return;
	}

	//Common method that sets the size of the output to the global variable size and sends the content of the global variable output 
	private void send(APDU apdu) {
		apdu.setOutgoing();
		apdu.setOutgoingLength(size);
		apdu.sendBytesLong(output, (short) 0, size);
	}
	
	//Simpler send method that assumes that APDU.buffer is updated with the output and sent instead. Saves resources, but needs some checks on the 
	//size of the incoming buffer
	private void sendBuff(APDU apdu) {
		apdu.setOutgoingAndSend((short) 0,size);
	}
    
}