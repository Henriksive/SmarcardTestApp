package henrik;


import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;
import javacard.security.AESKey;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.*;
import javacard.security.*;
import javacard.framework.JCSystem;

public class cardTest extends Applet implements ExtendedLength{
	//Try to allocate all variable here and do not create new ones 
	//The Public/Private key pair that this card will use
	private KeyPair keys;
	private KeyPair mKeys;
	private KeyPair sKeys; //PLACEHOLDER
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
	
	//Predefined Commands
	//private final byte SEND_TEST_SIGNATURE=(byte) 0x00;
	//private final byte SEND_PRV_EXP=(byte) 0x03;
	//private final byte SEND_KEY_LENGTH=(byte) 0x04;
	//private final byte SIGN_INPUT_DATA=(byte) 0x05;
	//private final byte SEND_AUTHENTICATED_PUB_EXP=(byte) 0x06;
	

	private final byte SEND_U_PUB_MOD=(byte) 0x01;
	private final byte SEND_U_PUB_EXP=(byte) 0x02;
	private final byte SIGN=(byte) 0x03;
	private final byte BINDING=(byte) 0x05;
	private final byte RSACRYPTO=(byte) 0x06;
	private final byte REFLECT=(byte) 0x08;
	private final byte AESCRYPTO=(byte) 0x09;
	

	
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
	byte[] h0Buffer = new byte[15000];
	//RSAPublicKey uPub;
	RSAPublicKey mPub;
	RSAPublicKey sPub; //PLACEHOLDER
	
	
	
	
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
			sKeys = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
			//keys = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
			
			//Set signature algorithm
			sig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
			
			sKeys.genKeyPair();
			sPub = (RSAPublicKey) sKeys.getPublic();
			
			mPub = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, (short) 512, false);
			
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
			
			
			cipherAES = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
			aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
			randomData = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
			rnd = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_RESET);
			randomData.generateData(rnd, (short)0, (short)rnd.length);
			aesKey.setKey(rnd, (short) 0);
			
			
		
			
			
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
		//output = new byte[32767];
		
		
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
		case SEND_U_PUB_MOD: 
			//Retrieve the modulus, store it in the output byte array and set the output length
			size = k.getModulus(output, (short) 0);
		    break;
//		  return exponent of public key  
		case SEND_U_PUB_EXP:  
//			Retrieve the public exponent, store it in the output byte array and set the output length
			size = k.getExponent(output, (short) 0);
			break;
//			return exponent of private key given correct pin authentication 
		case SIGN: 
			short bytesReadSign = apdu.setIncomingAndReceive();
			size = apdu.getIncomingLength();
			short echoOffsetSign = (short)0;
			while(bytesReadSign > 0){
				Util.arrayCopyNonAtomic(buff, dataOffset, h0Buffer, echoOffsetSign, bytesReadSign);
				echoOffsetSign += bytesReadSign;
				bytesReadSign = apdu.receiveBytes(dataOffset);
			}
			size = sig.sign(h0Buffer, (short) 0, bytesReadSign, output, (short) 0);
			break;
		case (byte) BINDING:
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
				size = (short) 3;
			}
			
			//Second transaction
			else if(p1 == (byte) 0x02){
				
				//SAFE COPY TO NEW BUFFER
				short bytesRead = apdu.setIncomingAndReceive();
				size = apdu.getIncomingLength();
				short echoOffset = (short)0;
				while(bytesRead > 0){
					Util.arrayCopyNonAtomic(buff, dataOffset, h0Buffer, echoOffset, bytesRead);
					echoOffset += bytesRead;
		            bytesRead = apdu.receiveBytes(dataOffset);
				}
				
				pincode.check(h0Buffer, (short) 0, PIN_SIZE); 
				output[0] = 0x05; //Type of transaction
				
				if(pincode.isValidated()){
					output[1] = 0x09;
					output[2] = 0x00;
					size = (short) 3;
					
				}
				else{
					output[1] = 0x00;
					output[2] = pincode.getTriesRemaining(); 
					size = (short) 3;
				}
			}
			
			else if(p1 == (byte) 0x03){
//				SAFE COPY TO NEW BUFFER
				short bytesRead = apdu.setIncomingAndReceive();
				short incomingLength = apdu.getIncomingLength();
				short echoOffset = (short)0;
				while(bytesRead > 0){
					Util.arrayCopyNonAtomic(buff, dataOffset, h0Buffer, echoOffset, bytesRead);
					echoOffset += bytesRead;
		            bytesRead = apdu.receiveBytes(dataOffset);
				}
				
				short modLength = Util.makeShort((byte)0x00, h0Buffer[0]);
				short expLenghtPos = (short) ((short) modLength + (short) 1);
				short expLength = Util.makeShort((byte)0x00, h0Buffer[expLenghtPos]); 
				short expStartPos = (short) (modLength + 2);
				
				
				
				
				
				
				
				
				
				
				
				
				
				boolean mPubIsOK = false;
				
				
				
				try{
					mPub.setModulus(h0Buffer, (short) 1, modLength);
					
					mPub.setExponent(h0Buffer, expStartPos, expLength);
					//size = mPub.getExponent(output, (short) 0);
					mPubIsOK = true;
					//size = mPub.getModulus(output, (short) 0);
					//if(true){
					//	break;
					//}
				}
				catch(CryptoException ex){
					output[0] = (byte) ex.getReason();
					output[1] = (byte) 0x02;
					size = 2;
					break;
				}
				catch(Exception ex){
					output[0] = (byte) 0x08;
					output[1] = (byte) 0x08;
					size = 2;
					break;
				}
				
				if(mPubIsOK && pincode.isValidated()){
					short totalsize = (short) (( (short) ( (short) mPub.getSize() + (short) k.getSize() + (short)  aesKey.getSize()) / (short) 8) + 10); //10 in header DANGEROUS
					byte[] packet = new byte[totalsize];
					short outputSize = 0;
					
					//AESKEY
					aesKey.getKey(packet, (short) 0);
					short AESKeyLength = (short) (aesKey.getSize()/8);
					//mPub
					Util.arrayCopyNonAtomic(h0Buffer, (short) 0, packet, AESKeyLength, (short) incomingLength);
					short AESmPubLenght = (short) (incomingLength + AESKeyLength);
					outputSize = AESmPubLenght;
					
					
					byte[] tempUPubArr = new byte[incomingLength];
					
					
					//UNDER HER ER FEILEN
					
					//uPub - modulus
					short tempLength = k.getModulus(tempUPubArr, (short)0);
					
					packet[outputSize] = (byte)tempLength;
					outputSize += 1;
					
					
					
					
					Util.arrayCopyNonAtomic(tempUPubArr, (short) 0, packet, (short) (AESmPubLenght+1), tempLength);
					outputSize += tempLength;
					
					
					
					//uPub - exponent
					tempLength = k.getExponent(tempUPubArr, (short) 0);
					packet[outputSize] = (byte)tempLength;
					outputSize +=1;
					Util.arrayCopyNonAtomic(tempUPubArr, (short) 0, packet, (short) (outputSize), tempLength);
					
					outputSize += tempLength;
					
					
					
					//Signing
					short signatureSize = sig.sign(packet, (short) 0, totalsize, h0Buffer, (short) 0);
					short h0UnencryptedLength = (short) (signatureSize + outputSize);
					
					//Create unencrypted package
					byte[] h0Unencrypted = new byte[h0UnencryptedLength];
					Util.arrayCopyNonAtomic(h0Buffer, (short) 0, h0Unencrypted, (short) 0, signatureSize);
					Util.arrayCopyNonAtomic(packet, (short) 0, h0Unencrypted, signatureSize, totalsize);
					
					//Util.arrayCopyNonAtomic(h0Unencrypted, (short) 0, output, (short) 0, h0UnencryptedLength);
					//size = h0UnencryptedLength;
					
					//Encrypt with sPub
					cipherRSA.init(sPub, Cipher.MODE_ENCRYPT);
					
					try{
						
						size = cipherRSA.doFinal(
					               h0Unencrypted, 
					               (short) 0,
					               h0UnencryptedLength,
					               output,
					               (short)0);
						
					             
					}
					catch(CryptoException ex){
						output[0] = 0x09;
						output[1] = (byte) ex.getReason();
						size = 2;
					}
					//size = h0UnencryptedLength;
					//size = sPub.getModulus(output, (short) 0);
				}
				else{
					output[0] = 0x09;
					output[1] = 0x09;
				}
				
			}
			else if(p1 == (byte) 0x09){
				pincode.resetAndUnblock();
				output[0] = 0x05;
				output[1] = 0x05;
				size = (short) 2;
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
		case (byte) RSACRYPTO:
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
		case (byte) REFLECT:	
			
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
			
		case (byte) AESCRYPTO:
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