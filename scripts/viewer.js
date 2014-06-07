var SALSA_IV = [0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a];
function storage_enum_file() {
	if(!navigator.getDeviceStorage)
		return false;
	var storage = navigator.getDeviceStorage('sdcard');
	if (!storage) {
		alert("No storage available!");
		return false;
	}
	var cursor = storage.enumerate();
	cursor.onsuccess = function() {
		if (this.result) {
			var file = this.result;
			$("#files").append($("<option>").text(file.name).attr("value",file.name));
			this.continue();
		}
	};
	cursor.onerror = function () {
		alert("no file found:" + this.error.name);
	};
}
function btn_openfile_clicked() {
	var storage = navigator.getDeviceStorage('sdcard');
	var filename = $("#files option:selected").val();
	var request = storage.get(filename);
	request.onsuccess = function () {
		read_file(this.result,function(){});
	};
	request.onerror = function () {
		alert("Unable to get the file:" + this.error.name);
	};


}
var ReadKdbxHeader = (function (){
	var KdbxHeaderFieldID =
	{
		"EndOfHeader" : 0,
		"Comment" : 1,
		"CipherID" : 2,
		"CompressionFlags" : 3,
		"MasterSeed" : 4,
		"TransformSeed" : 5,
		"TransformRounds" : 6,
		"EncryptionIV" : 7,
		"ProtectedStreamKey" : 8,
		"StreamStartBytes" : 9,
		"InnerRandomStreamID" : 10
	};
	function ReadKdbxHeader(file){
		this.header = {};
		this.file = file;
		this.offset = 0;
	
	}
	var readHeader = function(callback){
		//console.log("reading header");
		this.offset = 12;
		this.callback = callback;
		var that = this;
		var reader = new FileReader();
		reader.onload = function () {
			that.offset += 1;
			readFieldId(that,this.result);
		};
		reader.readAsArrayBuffer(this.file.slice(this.offset,this.offset+1));

	};
	var readFieldId = function (that,result){
		if(that.offset > that.file.size){
			console.log("offset over filesize");
			alert("something wrong reading header.");
			return false;
		}
		//console.log("read field id");
		var ID = new Uint8Array(result);
		that._ID = ID[0];
		//console.log(ID[0]);
		var reader = new FileReader();
		reader.onload = function () {
			that.offset += 2;
			readFieldLength(that,this.result);
		};
		reader.readAsArrayBuffer(that.file.slice(that.offset,that.offset+2));
	};
	var readFieldLength = function (that,result){
		//console.log("field length");
		var length = new Uint16Array(result);
		//console.log(length);
		var reader = new FileReader();
		reader.onload = function () {
			that.offset += length[0];
			readFieldData(that,this.result);
		};
		reader.readAsArrayBuffer(that.file.slice(that.offset,that.offset+length[0]));

	};
	var readFieldData = function (that,result){
		//console.log("field data")
		that.header[that._ID] = result;
		//var data = new Uint8Array(result);
		//console.log(array2hex(data));
		var reader = new FileReader();
		reader.onload = function () {
			that.offset += 1;
			if(that._ID == 0){
				that.callback();
			} else {
				readFieldId(that,this.result);
			}
		};
		reader.readAsArrayBuffer(that.file.slice(that.offset,that.offset+1));
	};
	var getHeader = function(field){
		return this.header[KdbxHeaderFieldID[field]];
	};
	ReadKdbxHeader.prototype = {
		constructor : ReadKdbxHeader,
		readHeader : readHeader,
		getHeader : getHeader
	};
	return ReadKdbxHeader;
})();
function array2hex(array){
	var hex = "";
	var table = [ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' ];
	for(var i=0;i<array.length;i++){
		hex += table[Math.floor(array[i]/16)];
		hex += table[array[i]%16];
	}
	return hex;
}
function array2hexp(array){
	console.log(array2hex(array));
}
var file_changed = function () {
	read_file(this.files[0],function(key,kdbxHeader){
		read_file_contents(key,kdbxHeader,process_kdbxContent);
	});


};
function read_file_contents(key,kdbxHeader,callback){
	//console.log(kdbxHeader.offset-1);
	var reader = new FileReader();
	reader.onload = function () {
		//var data = new Uint8Array(this.result);
		var data = this.result;
		var importKeyOp = crypto.subtle.importKey("raw", key, { name: "AES-CBC"	}, true, ['decrypt']);
		importKeyOp.then(function (importedKey) {
			//console.log("import key");
			var aesAlgorithmDecrypt = {
				name: "AES-CBC",
				iv: kdbxHeader.getHeader('EncryptionIV')
			};

			var decryptOp = crypto.subtle.decrypt(aesAlgorithmDecrypt, importedKey, data);
			return decryptOp;
		}).then(function(plainText){
			var offset = 0;
			var startBytes = kdbxHeader.getHeader("StreamStartBytes");
			startBytes = new Uint8Array(startBytes);
			offset += startBytes.length;

			var index = plainText.subarray(offset,offset+4);offset += 4;
			index = Uint8x4_to_Uint32(index);


//			index = index[0]|(index[1]<<8)|(index[2]<<16)|(index[3]<<24);//I think 2^31-1 is enough for index...
			
			var hash = plainText.subarray(offset, offset+32);offset += 32;

			var length = plainText.subarray(offset,offset+4);offset += 4;
			length = Uint8x4_to_Uint32(length);
			//TODO: implement https://github.com/NeoXiD/keepass.io/blob/master/lib/hbio.js
			crypto.subtle.digest({ name: "SHA-256" }, plainText.subarray(offset,offset+length)).then(function(digest){
				var kdbxContentSubarray = plainText.subarray(offset,offset+length);
				var kdbxContent,kdbxContentStr;
				if(array2hex(digest) == array2hex(hash)){
					var compressionFlag = (new Uint32Array(kdbxHeader.getHeader("CompressionFlags")))[0];
					var parser = new DOMParser();
					if(compressionFlag){
						var gunzip = new Zlib.Gunzip(kdbxContentSubarray);
						var plain = gunzip.decompress();
						kdbxContentStr = String.fromCharCode.apply(null, plain);
						kdbxContent = parser.parseFromString(String.fromCharCode.apply(null, plain),"text/xml");
					} else {
						kdbxContentStr = String.fromCharCode.apply(null, kdbxContentSubarray);
						kdbxContent = parser.parseFromString(String.fromCharCode.apply(null, kdbxContentSubarray),"text/xml");
					}
					if(callback)
					callback(kdbxHeader,kdbxContent);
				} else {
					console.log("Block hash mismatch");
				}
			});


			//while(length != 0 && offset < plainText.length);
			//console.log(plainText);
			//console.log(String.fromCharCode.apply(null, new Uint8Array(plainText)));
		});
	};
	reader.readAsArrayBuffer(kdbxHeader.file.slice(kdbxHeader.offset-1));
}
function read_file(file,callback){
		console.log("Get the file" + file.name);
		var sigblob = file.slice(0,8);
		var reader = new FileReader();
		reader.onload = function () {
			if(btoa(String.fromCharCode.apply(null, new Uint8Array(this.result))) == "A9mimmf7S7U="){
				console.log("found supported kdbx file signeture");
				var a = new ReadKdbxHeader(file);
				var cb = function () {
					var cred = new Credentials();
					cred.genCompositeHash(function(compositeHash) {
						var tk = new TransformKey();
						var rounds = new Uint32Array(a.getHeader("TransformRounds"));
						tk.rounds = rounds[0]; //read only first 32bit. I think this is enough...
						//tk.rounds = 10;
						tk.seed = new Uint8Array(a.getHeader("TransformSeed"));
						tk.key = compositeHash;
						console.time("Transform Key");
						tk.onfinal = function (result) {
							console.timeEnd("Transform Key");
							var masterseed = new Uint8Array(a.getHeader("MasterSeed"));
							var c = new Uint8Array(masterseed.length + result.length);
							c.set(masterseed);
							c.set(result, masterseed.length);
							result = c;
							crypto.subtle.digest({ name: "SHA-256" }, new Uint8Array(result)).then(function(masterKey){
								callback(masterKey,a);
							});

						};
						tk.start();
					});
				};
				a.readHeader(cb);
			}
		};
		reader.readAsArrayBuffer(sigblob);

}
document.getElementById("btn_openfile").addEventListener("click",btn_openfile_clicked);
document.getElementById("file").addEventListener("change",file_changed);
function myECB(key,data,cb){
	var ecbqueue = [];

	for(var i=0;i<data.length;i+=16){
		if(data.slice){
		ecbqueue.push(blockECB(key, new Uint8Array(data.slice(i,i+16))));
		} else if (data.subarray){
		ecbqueue.push(blockECB(key, new Uint8Array(data.subarray(i,i+16))));
		}
	}
	Promise.all(ecbqueue).then(function (arr){
		var length = 0;
		var offset = 0;
		for(var i=0;i<arr.length;i++){
			length += arr[i].length;
		}
		//console.log(length);
		var concated = new Uint8Array(length);
		for(i=0;i<arr.length;i++){
			concated.set(arr[i],offset);
			offset += arr[i].length;
		}
		//array2hexp(concated);
		cb(concated);
	});
}
function blockECB(key, data) {

	var importKeyOp = crypto.subtle.importKey("raw", key, { name: "AES-CBC"	}, true, ['encrypt']);
	return importKeyOp.then(function (digestKey) {
//          console.log("Digest key created.");

		var aesAlgorithmEncrypt = {
			name: "AES-CBC",
			iv: new Uint8Array(Array(16))
		};

		var encryptOp = crypto.subtle.encrypt(aesAlgorithmEncrypt, digestKey, data);
		return encryptOp;
	}).then(function (cipherText) {
		return new Promise(
			function (resolve, reject) {
				resolve(cipherText.subarray(0, 16));
			});
	});
}
var TransformKey = (function() {
	var TransformKey = function () {
		this.round = 0;
		this.rounds = 5;
		this.onfinal = function (result) {
			array2hexp(result);
		};
		this.key = new Uint8Array(Array(32));
		this.seed = new Uint8Array(Array(32));
		this.key = new Uint8Array([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]);
		this.seed = new Uint8Array([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]);
		//return this;
	};
	var finalRound = function(result){
		var that = this;
		crypto.subtle.digest({ name: "SHA-256" }, result).then(function(digest){
			that.onfinal(digest);
		});

	};
	var transformRound = function (result){
//		console.log("transform round");
//		console.log(this.round);
		if(this.round < this.rounds-1){
			this.round++;
			myECB(this.seed, result,transformRound.bind(this));
		} else {
			finalRound.call(this,result);
		}
	};
	TransformKey.prototype = {
		constructor : TransformKey,
		start : function () {
			myECB(this.seed, this.key,transformRound.bind(this));
		},
		transformRound : transformRound
	
	};
	return TransformKey;
})();
function str2ab (str) {
		var buf = new ArrayBuffer(str.length);
		var bufView = new Uint8Array(buf);
		for (var i=0; i<str.length; i++) {
			bufView[i] = str.charCodeAt(i);
		}
		return buf;
}
function Uint8x4_to_Uint32 (uint8array) {
	//TODO: endian?
	var ab = new ArrayBuffer(4);
	var ab_v = new DataView(ab);
	var pos = 0;
	ab_v.setUint8(pos++, uint8array[3]);
	ab_v.setUint8(pos++, uint8array[2]);
	ab_v.setUint8(pos++, uint8array[1]);
	ab_v.setUint8(pos++, uint8array[0]);
	return ab_v.getUint32(0);
}
var Credentials = (function() {
	var Credentials = function () {
		this.password = $("#pass").val() || "test";
	};
	var genCompositeHash = function (callback){
		addPassword.call(this).then(function(digest){
			return crypto.subtle.digest({ name: "SHA-256" }, new Uint8Array(digest));
		}).then(callback);
	};
	var addPassword = function (){
		return crypto.subtle.digest({ name: "SHA-256" }, new Uint8Array(str2ab(this.password)));
	};
	Credentials.prototype = {
		constructor : Credentials,
		genCompositeHash : genCompositeHash
	};
	return Credentials;
})();
var Unprotect = (function() {
	var Unprotect = function () {
		this.salsa20 = null;
	};
	var xor = function(input, key){
		var output = [];
		for(var i=0;i<input.length;i++){
			output[i] = input[i] ^ key[i];
		}
		return String.fromCharCode.apply(null, output);
	};
	var unprotect = function (pw){
		pw = atob(pw);
		pw = str2ab(pw);
		pw = new Uint8Array(pw);
		var key = this.salsa20.getBytes(pw.length);
		return xor(pw,key);
	};
	var setSalsa = function (key,cb){
		var that = this;
		crypto.subtle.digest({ name: "SHA-256" }, key).then(function(digest){
			array2hexp(digest);
			that.salsa20 = new Salsa20(digest,SALSA_IV);
			cb();
		});
	};
	Unprotect.prototype = {
		constructor : Unprotect,
		unprotect : unprotect,
		setSalsa: setSalsa
	};
	return Unprotect;
})();
function process_kdbxContent(kdbxHeader,kdbxContent){
		var up = new Unprotect();
		console.log(kdbxHeader.getHeader("ProtectedStreamKey"));
		up.setSalsa(kdbxHeader.getHeader("ProtectedStreamKey"),function(){
			var nodeSnapshot = kdbxContent.evaluate("//Value[@Protected='True']", kdbxContent, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null );
			for(var i=0;i<nodeSnapshot.snapshotLength;i++){
				var thisNode = nodeSnapshot.snapshotItem(i);
				thisNode.textContent = up.unprotect(thisNode.textContent);
				thisNode.removeAttribute("Protected");

			}
			var iterator = kdbxContent.evaluate("//Key[contains(text(),'Password')]/../Value", kdbxContent, null, XPathResult.ORDERED_NODE_ITERATOR_TYPE, null );

			try {
				var thisNode = iterator.iterateNext();

				while (thisNode) {
					console.log( thisNode.textContent );
					thisNode = iterator.iterateNext();
				}	
			}
			catch (e) {
				console.log( 'Error: Document tree modified during iteraton ' + e );
			}
			$("#file-content").val((new XMLSerializer()).serializeToString(kdbxContent));
		});
}
storage_enum_file();
