var express = require('express');
var app = express();
var fs = require('fs');
var async = require('async');
var bodyParser = require('body-parser');
var through = require('through');
var path = require('path');
require('dotenv').config();
var localAssetsDir = __dirname + '/public';
var multer = require('multer');
var path = require('path');

var storj = require('storj-lib');
var storj_utils = require('storj-lib/lib/utils');
var api = 'https://api.storj.io';
var client;

//var KEYRING_PASS = 'somepassword';
var KEYRING_PASS = process.env.KEYRING_PASS;
var keyring = storj.KeyRing('./');

// Storj variables
var STORJ_EMAIL = process.env.STORJ_EMAIL;
var STORJ_PASSWORD = process.env.STORJ_PASSWORD;
var PORT = process.env.PORT;
/*
  Get and/or generate mnemonic for you on load.
  !! Important: you'll need to manually add the contents of the file in the
  key.ring directory to your Heroku config variables either through the GUI or
  the command line:
  `heroku config:set STORJ_MNEMONIC=<VALUE FROM .ENV FILE>`
*/
var STORJ_MNEMONIC = process.env.STORJ_MNEMONIC || generateMnemonic();

var storjCredentials = {
    email: STORJ_EMAIL,
    password: STORJ_PASSWORD
};

// Helps to break up endpoint logs
var separator = function() {
    return console.log('================================');
};

//app.set('port', (process.env.PORT || 5000));
app.set('port', (PORT || 8080));

app.use(express.static(__dirname + '/public'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: true
}));

/* Endpoints */

/**
 * Simple endpoint to make sure your STORJ_EMAIL and STORJ_PASSWORD environment
 * variables are on your .env file
 */
app.get('/user/retrieve', function(req, res) {
    separator();
    console.log('Retrieving basic auth credentials...');
    console.log('Retrieving basic auth credentials...', storjCredentials);
    res.status(200).send(storjCredentials);
});

/**
 * Authenticates your user with storj.BridgeClient. The authorized instance
 * is saved into a 'global' variable 'client'. This allows you to use this same
 * authorized instance for future interactions without have to re-authenticate
 * every single time.
 */
app.get('/user/authenticate/user-pass', userpass);

function userpass(req, res) {
    separator();
    console.log('Attempting to log in with basic auth...');
    if (!STORJ_EMAIL || !STORJ_PASSWORD) {
        return res.status(400).send('No credentials. Make sure you have a .env file with KEY=VALUE pairs')
    }
    client = storj.BridgeClient(api, {
        basicAuth: storjCredentials
    });
    console.log('Logged in with basic auth');
    if (res)
        res.status(200).send('successful');
}



/**
 * Generates a keypair and adds the public key to the storj.BridgeClient and
 * stores the private key on your local .env file. You'll want to take this
 * key and save it to your heroku config variables either through the GUI or
 * with:
 * `heroku config:set STORJ_PRIVATE_KEY=<VALUE FROM .ENV FILE>`
 */
app.get('/keypair/generate', function(req, res) {
    separator();
    if (process.env.STORJ_PRIVATE_KEY) {
        console.warn('Private key already exists');
        return res.status(400).send('duplicate');
        // You can actually make as many private keys as you want, but we're just
        // going to restrict ourselves to one for simplicity. This also makes it
        // easier when deploying applications to Heroku. If you want to generate
        // more keypairs, then be sure to store them under unique KEY names in
        // your .env files/heroku config variables
    }

    // Generate keypair
    var keypair = storj.KeyPair();
    console.log('Generating Storj keypair...');

    if (!client) {
        console.warn('User is not authenticated. Authenticate with basic auth, or with keypair auth if you\'ve already generated a keypair');
        return res.status(400).send('No authentication. Make sure to authenticate with Basic Authentication first.');
    }

    // Add the keypair public key to the user account for Authentication
    console.log('Adding public key to storj.BridgeClient...');
    client.addPublicKey(keypair.getPublicKey(), function() {
        // Save the private key for using to login later
        console.log('Public key added to storj.BridgeClient, saving to .env file. Make sure to add this key to your Heroku config variables');

        fs.appendFileSync('./.env', `STORJ_PRIVATE_KEY=${keypair.getPrivateKey()}`);

        // Send back sucess to client
        res.status(200).send(keypair.getPublicKey());
    });
});

/**
 * Retrieves all keypairs registered with storj.bridgeClient
 */
app.get('/keypair/retrieve', function(req, res) {
    separator();
    if (!client) {
        console.warn('User is not authenticated. Authenticate with basic auth, or with keypair auth if you\'ve already generated a keypair');
        return res.status(400).send('No authentication. Make sure to authenticate with Basic Authentication or Key Pair authentication (if you have already generated a key pair).');
    }

    console.log('Getting public keys...');

    client.getPublicKeys(function(err, keys) {
        if (err) {
            return console.log('error', err.message);
        }

        // Print out each key for your enjoyment on the console
        keys.forEach(function(key) {
            console.log('key info', key);
        });

        // Send back key pair info to client
        res.status(200).send(keys);
    })
});

/**
 * Authenticates user with storj.BridgeClient using keypair instead of basic
 * auth
 */
app.get('/keypair/authenticate', function(req, res) {
    separator();
    // Load saved private key
    var privateKey = process.env.STORJ_PRIVATE_KEY;

    console.log('Retrieved privateKey: ', privateKey)
    console.log('Matching privateKey with public key registered with storj');
    var keypair = storj.KeyPair(privateKey);

    // Login using the keypair
    console.log('Logging in with keypair...')
    client = storj.BridgeClient(api, {
        keyPair: keypair
    });
    console.log('Logged in with keypair');
    res.status(200).send('successful');
});

/**
 * Creates a bucket on your Storj account
 */
app.post('/buckets/create', function(req, res) {
    separator();
    // Settings for bucket
    var bucketInfo = {
        name: req.body.name
    };

    // Create bucket
    console.log('Creating bucket ', req.body.name, '...');
    client.createBucket(bucketInfo, function(err, bucket) {
        if (err) {
            return console.log('error', err.message);
        }
        console.log(bucket, ' created!');
        res.status(200).send(bucket);
    });
});

/**
 * Lists all buckets on your account
 */
app.get('/buckets/list', function(req, res) {
    separator();
    console.log('Getting buckets...')
    client.getBuckets(function(err, buckets) {
        if (err) {
            return console.log('error', err.message);
        }
        console.log('Retrieved buckets', buckets);
        res.status(200).send(buckets);
    });
});

/**
 * Uploads a file to a bucket. For simplicity, the file and bucket are
 * predetermined and hardcoded. The basic steps of uploading a file are:
 * 1. Decide what bucket and file you're going to upload.
 *   a. Retrieve ID of bucket
 *   b. Retrieve path to file
 *   c. Retrieve name of file
 * 2. Create a filekey based on your user name, bucketId, and filename - these
 *    variables are then taken and combined with your keyring mnemonic to
 *    generate a deterministic key to encrypt the file.
 * 3. Create a temporary path to store the encrypted file (remember, files
 *    should be encrypted before they are uploaded)
 * 4. Instantiate encrypter
 * 5. Encrypt the file by creating a stream, piping the contents of the stream
 *    through your encrypter, and then taking the result and writing it to
 *    the temporary path determined in step 3
 * 6. Create a token for uploading the file to the bucket
 * 7. Store file in bucket
 * 8. Bonus points: Clean up your encrypted file that you made
 *
 * Note: We didn't do this check here, but you could also check to make sure
 * that the file name doesn't already exist in the bucket. Currently this will
 * just overwrite any file with the same name.
 */
app.get('/files/upload', function(req, res) {
    separator();
    console.log('Retrieving buckets...')
    // Step 1
    client.getBuckets(function(err, buckets) {
        if (err) {
            return console.error(err.message);
        }

        // Step 1a) Use the first bucket
        var bucketId = buckets[0].id;
        console.log('Uploading file to: ', bucketId);

        // Step 1b) Path of file
        var filepath = './public/grumpy.jpg';
        console.log('Path of file: ', filepath);

        // Step 1c) Name of file
        var filename = 'grumpy.jpg';
        console.log('Name of file: ', filename);

        // Step 2) Create a filekey with username, bucketId, and filename
        var filekey = getFileKey(STORJ_EMAIL, bucketId, filename);

        // Step 3) Create a temporary path to store the encrypted file
        var tmppath = filepath + '.crypt';

        // Step 4) Instantiate encrypter
        var encrypter = new storj.EncryptStream(filekey);

        // Step 5) Encrypt file
        fs.createReadStream(filepath)
            .pipe(encrypter)
            .pipe(fs.createWriteStream(tmppath))
            .on('finish', function() {
                console.log('Finished encrypting');

                // Step 6) Create token for uploading to bucket by bucketId
                client.createToken(bucketId, 'PUSH', function(err, token) {
                    if (err) {
                        console.log('error', err.message);
                    }
                    console.log('Created token', token.token);

                    // Step 7) Store the file
                    console.log('Storing file in bucket...');
                    client.storeFileInBucket(bucketId, token.token, tmppath,
                        function(err, file) {
                            if (err) {
                                return console.log('error', err.message);
                            }
                            console.log('Stored file in bucket');
                            // Step 8) Clean up and delete tmp encrypted file
                            console.log('Cleaning up and deleting temporary encrypted file...');
                            fs.unlink(tmppath, function(err) {
                                if (err) {
                                    return console.log(err);
                                }
                                console.log('Temporary encrypted file deleted');
                            });

                            console.log(`File ${filename} successfully uploaded to ${bucketId}`);
                            res.status(200).send(file);
                        });
                });
            });
    });
});

/**
 * Lists all files in buckets
 */
app.get('/files/list', function(req, res) {
    separator();
    // Create object to hold all the buckets and files
    var bucketFiles = {};

    // Get buckets
    console.log('Getting buckets...')
    client.getBuckets(function(err, buckets) {
        if (err) {
            return console.log('error', err.message);
        }

        // Get all the buckets, and then return the files in the bucket
        // Assign files to bucketFiles
        async.each(buckets, function(bucket, callback) {
            console.log('bucket', bucket.id);
            client.listFilesInBucket(bucket.id, function(err, files) {
                if (err) {
                    return callback(err);
                }
                // bucketFiles.myPictureBucket = [];
                bucketFiles[bucket.name] = files;
                callback(null);
            })
        }, function(err) {
            if (err) {
                return console.log('error');
            }
            console.log('bucketFiles retrieved: ', bucketFiles);
            res.status(200).send(bucketFiles);
        });
    });
});

app.get('/:bucketId/:fname', function(req, res) {
    separator();

    // Step 1a) Retrieve ID of bucket
    var bucketId = req.params.bucketId;
    console.log('Got bucketId', bucketId);

    // Listen for the close and finish events on the response. Only one will fire,
    // depending on how the response is handled.
    res
        // "close" from the documentation:
        // --
        // >> Indicates that the underlying connection was terminated before
        // >> response.end() was called or able to flush.
        .on(
            "close",
            function handleCloseEvent() {

                console.log("Request closed prematurely.");

            }
        )
        // "finish" from the documentation:
        // --
        // >> Emitted when the response has been sent. More specifically, this event is
        // >> emitted when the last segment of the response headers and body have been
        // >> handed off to the operating system for transmission over the network. It
        // >> does not imply that the client has received anything yet.... After this
        // >> event, no more events will be emitted on the response object.
        .on(
            "finish",
            function handleFinishEvent() {

                console.log("Request finished successfully.");

            }
        );

    // Step 1b) Get the fileId of the file we want to download.
    client.listFilesInBucket(bucketId, function(err, files) {
        if (err) {
            console.log('error', err.message);
            res.writeHead(404, {
                "Content-Type": "text/plain"
            });
            res.write("404 Not Found\n");
            res.end();
            return;
        }

        var filename = req.params.fname;

        // Get grumpy file
        //var grumpyFile = files.find(function(file) {
        var downFile = files.find(function(file) {
            return file.filename.match(filename);
        });

        if (!downFile) {
            console.log("error: file not found\n");
            res.writeHead(404, {
                "Content-Type": "text/plain"
            });
            res.write("404 Not Found\n");
            res.end();
            return;
        }

        // Start our response.
        res.writeHead(
            200,
            "OK", {
                "Content-Type": "image/jpeg"
            }
        );

        // Step 1b)
        var fileId = downFile.id;

        // Note: make sure the filename here is the same as when you generated
        // the filename when you uploaded. Because the filekey was generated
        // using the filename, they MUST match, otherwise the key will not be
        // the same and you cannot download the file

        // Step 2) Create filekey
        var filekey = getFileKey(STORJ_EMAIL, bucketId, filename);

        var target = res;

        // Step 4) Instantiate decrypter
        var decrypter = new storj.DecryptStream(filekey);

        var received = 0;

        console.log('bucketId : %s, fileId : %s', bucketId, fileId);

        // Step 5) Download the file
        console.log('Creating file stream...');
        client.createFileStream(bucketId, fileId, {
                exclude: []
            },
            function(err, stream) {
                if (err) {
                    console.log('error', err.message);
                    return;
                }

                // Handle stream errors
                stream.on('error', function(err) {
                        console.log('warn', 'Failed to download shard, reason: %s', [err.message]);
                        // Delete the partial file if there's a failure
                        fs.unlink(filepath, function(unlinkFailed) {
                            if (unlinkFailed) {
                                return console.log('error', 'Failed to unlink partial file.');
                            }
                            if (!err.pointer) {
                                return;
                            }
                        });
                    }).pipe(through(function(chunk) {
                        received += chunk.length;
                        console.log('info', 'Received %s of %s bytes', [received, stream._length]);
                        this.queue(chunk);
                    })).pipe(decrypter)
                    .pipe(res);
            });
    });
});

//multer uploader
var storage = multer.diskStorage({ //multers disk storage settings
    destination: function(req, file, cb) {
        cb(null, './uploads/')
    },
    filename: function(req, file, cb) {
        //var datetimestamp = Date.now();
        //cb(null, file.fieldname + '-' + datetimestamp + '.' + file.originalname.split('.')[file.originalname.split('.').length - 1])
        cb(null, file.originalname);
    },
    limits: {
        files: 1,
        fileSize: 2 * 1024 * 1024, //2mb
    }
});

var upload = multer({ //multer settings
    storage: storage
}).single('file');


/** API path that will upload the files */
app.post('/files/upload/:bucketId', function(req, res) {
    console.log('/files/upload');
    upload(req, res, function(err) {
        if (err) {
            res.json({
                error_code: 1,
                err_desc: err
            });
            return;
        }
        if (!req.file) {
            return
        }

        var bucketId = req.params.bucketId;
        console.log('Uploading file to bucketId: ', bucketId);

        console.log('file data: ', req);

        // Step 1b) Path of file
        var filepath = req.file.path;
        console.log('Path of file: ', filepath);

        // Step 1c) Name of file
        //var filename = 'grumpy.jpg';
        var filename = req.file.originalname;
        console.log('Name of file: ', filename);

        // Step 2) Create a filekey with username, bucketId, and filename
        var filekey = getFileKey(STORJ_EMAIL, bucketId, filename);

        // Step 3) Create a temporary path to store the encrypted file
        var tmppath = filepath + '.crypt';

        // Step 4) Instantiate encrypter
        var encrypter = new storj.EncryptStream(filekey);

        // Step 5) Encrypt file
        fs.createReadStream(filepath)
            .pipe(encrypter)
            .pipe(fs.createWriteStream(tmppath))
            .on('finish', function() {
                console.log('Finished encrypting');

                // Step 6) Create token for uploading to bucket by bucketId
                client.createToken(bucketId, 'PUSH', function(err, token) {
                    if (err) {
                        console.log('error', err.message);
                    }
                    console.log('Created token', token.token);

                    // Step 7) Store the file
                    console.log('Storing file in bucket...');
                    client.storeFileInBucket(bucketId, token.token, tmppath,
                        function(err, file) {
                            if (err) {
                                return console.log('error', err.message);
                            }
                            console.log('Stored file in bucket');
                            // Step 8) Clean up and delete tmp encrypted file
                            console.log('Cleaning up and deleting temporary encrypted file...');
                            fs.unlink(tmppath, function(err) {
                                if (err) {
                                    return console.log(err);
                                }
                                console.log('Temporary encrypted file deleted');
                            });

                            fs.unlink(filepath, function(err) {
                                if (err) {
                                    return console.log(err);
                                }
                                console.log('Uploaded file deleted');
                            });

                            console.log(`File ${filename} successfully uploaded to ${bucketId}`);
                            //res.status(200).send(file);
                        });
                });
            });

        var filePath = req.get('host') + "/" + bucketId + "/" + filename;

        console.log(`Storj filePath : ${filePath}`);

        res.json({
            file_path: filePath,
            error_code: 0,
            err_desc: null
        });
    })

});


app.listen(app.get('port'), function() {
    separator();
    console.log('Node app is running on port', app.get('port'));
    userpass();
});

/**
 * Deterministically generates filekey to upload/download file based on
 * mnemonic stored on keyring. This means you only need to have the mnemonic
 * in order to upload/download on different devices. Think of the mnemonic like
 * an API key i.e. keep it secret! keep it safe!
 */
function getFileKey(user, bucketId, filename) {
    console.log('Generating filekey...')
    generateMnemonic();
    var realBucketId = storj_utils.calculateBucketId(user, bucketId);
    var realFileId = storj_utils.calculateFileId(bucketId, filename);
    var filekey = keyring.generateFileKey(realBucketId, realFileId);
    console.log('Filekey generated!');
    return filekey;
}

/**
 * This generates a mnemonic that is used to create deterministic keys to
 * upload and download buckets and files.
 * This puts the mnemonic on your keyring (only one mnemonic is held per
 * keyring) and also writes the mnemonic to your local .env file.
 */
function generateMnemonic() {
    console.log('Attempting to retrieve mnemonic');
    var mnemonic = keyring.exportMnemonic();
    var newMnemonic;

    if (mnemonic) {
        console.log('Mnemonic already exists', mnemonic);
    } else {
        console.log('Mnemonic doesn\'t exist or new keyring');
        try {
            keyring.importMnemonic(process.env.STORJ_MNEMONIC);
        } catch (err) {
            console.log('process.env.STORJ_MNEONIC', err);
            try {
                keyring.importMnemonic(keyring.generateDeterministicKey());
            } catch (err) {
                console.log('generateDeterministicKey', err);
            }
        }
    }

    console.log('Mnemonic successfully retrieved/generated and imported');
    if (!process.env.STORJ_MNEMONIC) {
        console.log('Mnemonic not saved to env vars. Saving...');
        // Write mnemonic to .env file
        fs.appendFileSync('./.env', `STORJ_MNEMONIC="${mnemonic || newMnemonic}"`);
        console.log('Mnemonic written to .env file. Make sure to add this to heroku config variables with \'heroku config:set STORJ_MNEMONIC="<VALUE FROM .ENV FILE>\'');
        return;
    }
}
