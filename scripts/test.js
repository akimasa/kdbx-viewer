document.getElementById("file").removeEventListener("change",file_changed,false);
var file_changed = function () {
	var that = this;
	var originalTimeout;
	/*
	beforeEach(function() {
		originalTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
		jasmine.DEFAULT_TIMEOUT_INTERVAL = 20000;
	});
	*/
	describe("file changed", function() {
		it("reads file", function(done) {
			read_file(that.files[0],function(key,kdbxHeader){

				read_file_contents(key,kdbxHeader,function(a){
					if(a)
					done();
				});
				
			});
		});

	});
	/*
	afterEach(function() {
		jasmine.DEFAULT_TIMEOUT_INTERVAL = originalTimeout;
	});
	*/
	jasmine.execute();


};

document.getElementById("file").addEventListener("change",file_changed);


describe("myECB", function() {
	it("encrypts correct", function(done) {

		myECB(new Uint8Array(str2ab("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")),new Uint8Array(str2ab("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")),function(a){
			if(array2hex(a) == "2ccd45896fc3525e03c7cb97b66895ff2ccd45896fc3525e03c7cb97b66895ffca74478bef3bf13d0acf1a5f4209b46cca74478bef3bf13d0acf1a5f4209b46c"){
				done()
			}
		});
	});
});
describe("TransformKey", function() {
	it("transforms key correct",function(done) {
		var tk = new TransformKey();
		tk.key = new Uint8Array([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]);
		tk.seed = new Uint8Array([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]);
		tk.onfinal = function(result){
			if(array2hex(result) == "e40081719ed537b65d49907a1606cca83cf8b28b54e25be05cbebc6090117fc8")
			done();
		};
		tk.start();
	});
});
describe("Credentials", function() {
	it("genCompositeHash generates correct",function(done) {
		var cred = new Credentials();
		cred.password = "test";
		cred.genCompositeHash(function(hash){
			if(array2hex(hash) == "954d5a49fd70d9b8bcdb35d252267829957f7ef7fa6c74f88419bdc5e82209f4");
			done();
		});
	});
});
