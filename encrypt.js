#!/usr/bin/env node

if(process.argv.length < 4) {
	console.log("Usage: ./encrypt.js filename password");
	return;
}

crypto = require("crypto");
fs = require('fs');
fs.readFile(process.argv[2], 'utf8', function(err, data) {
	if(err) {
		console.log("Could not open file " + process.argv[2]);
		console.log(err);
		return;
	}

	var key = process.argv[3];
	var plaintext = data;
	var rawContent = new Buffer(plaintext);

	var rawKey = new Buffer(key);
	window.crypto.subtle.importKey("raw", rawKey,  { name: "PBKDF2", }, true, ["deriveKey"])
	//-------------------------------------------------------
	.then(function(key){
		window.crypto.subtle.deriveKey(
			{ "name": "PBKDF2", salt: new Uint8Array(16), //Constant zeros, on purpose.
	        iterations: 1000, hash: {name: "SHA-512"}, },
	    	key, { name: "AES-GCM", length: 256, }, false,  ["encrypt", "decrypt"]
		)
		//-------------------------------------------------------
		.then(function(key){
			var iv = window.crypto.getRandomValues(new Uint8Array(12));
			window.crypto.subtle.encrypt( { name: "AES-GCM", iv: iv, tagLength: 128, },
		    	key, rawContent 
			)
			//-------------------------------------------------------
			.then(function(encrypted){
			    var totalBuffer = appendBuffer(iv, encrypted);
			    var encodedCiphertext = btoa(String.fromCharCode.apply(null, new Uint8Array(totalBuffer)));
			    
			    console.log(encodedCiphertext);
			})
			.catch(function(err){
				console.error("Caught an error while encrypting.")
			    console.error(err);
			});
		})
		.catch(function(err){
			console.error("Caught an error while trying to PBKDF2 a key.")
		    console.error(err);
		});
	})
	.catch(function(err){
		console.error("Caught an error while trying to impoer the password as a key.")
		console.error(err);
	});
});
