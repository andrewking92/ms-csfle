# 0. Install libmongocrypt

sudo vi /etc/yum.repos.d/libmongocrypt.repo

[libmongocrypt]
name=libmongocrypt repository
baseurl=https://libmongocrypt.s3.amazonaws.com/yum/amazon/2/libmongocrypt/1.7/x86_64
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/libmongocrypt.asc


sudo yum install -y libmongocrypt


# 1. Setup KMS and CMK. Assume role
aws sts assume-role --role-arn ''  --role-session-name "RoleSession1" > token


# 2. Create key vault on MongoDB cluster
mongosh <CONNECTION_STRING> --eval 'db.getSiblingDB("__encryption").getCollection("__keyVault").createIndex({keyAltNames: 1},{unique: true, partialFilterExpression: {"keyAltNames": {"$exists": true}}})'



# 3. Setup Privileges. Generate public:private keypair and create a custom role and DB user

# CREDS="public:private"
# PROJECTID=""
# PASSWORD=""


curl -u $CREDS --digest \
-H 'Content-Type: application/json' \
-X POST "https://cloud.mongodb.com/api/atlas/v1.0/groups/$PROJECTID/customDBRoles/roles" \
--data '
{
 "actions": [
   {
     "action": "FIND",
     "resources": [
       {
         "collection": "__keyVault",
         "db": "__encryption"
       }
     ]
   },
   {
     "action": "INSERT",
     "resources": [
       {
         "collection": "__keyVault",
         "db": "__encryption"
       }
     ]
   }
 ],
 "inheritedRoles": [
   {
     "db": "companyData",
     "role": "readWrite"
   }
 ],
 "roleName": "cryptoClient"
}'

curl -u $CREDS --digest \
-H 'Content-Type: application/json' \
-X POST "https://cloud.mongodb.com/api/atlas/v1.0/groups/$PROJECTID/databaseUsers" \
--data '
{
 "username": "mongoCryptoClient",
 "databaseName": "admin",
 "password": //,
 "roles": [
   {
     "databaseName": "admin",
     "roleName": "cryptoClient"
   }
 ]
}'




# 4. Launch mongosh with no db

TOKEN=$(cat token) mongosh --nodb



const token=JSON.parse(process.env.TOKEN)
const provider = {
 "aws": { // <-- KMS provider name
   "accessKeyId": token.Credentials.AccessKeyId,
   "secretAccessKey": token.Credentials.SecretAccessKey,
   "sessionToken": token.Credentials.SessionToken
 }
}
const autoEncryptionOpts = {
 kmsProviders : provider,
 schemaMap: {},
 bypassAutoEncryption: true, // <-- we want to manually decrypt
 keyVaultNamespace: "__encryption.__keyVault"
}

encryptedClient = Mongo("mongodb+srv://mongoCryptoClient:$PASSWORD@xxx/companyData", autoEncryptionOpts)

keyVault = encryptedClient.getKeyVault()

keyVault.createKey(
 "aws", // <-- KMS provider name
 {"region": "eu-west-1", "key": "a655095d-b4d7-4148-985b-e541915a1416"}, // <-- CMK info (specific to AWS in this case)
 ["dataKey1"] // <-- Key alternative name
)

// Retrieve all the keys
keyVault.getKeys()



# 5. Create json schema validator

mongosh "mongodb+srv://$USER:$PSWD@xxx"

db.getSiblingDB("companyData").createCollection("employee",
 {
   "validator": {
     "$jsonSchema": {
       "bsonType" : "object",
       "encryptMetadata" : {
         "keyId" : [
           UUID("6dc2b910-0f62-4f77-99f7-5be04c59fd6e") 
         ],
         "algorithm" : "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
       },
       "properties" : {
         "name" : {
		"bsonType": "object",
		  "properties" : {
		    "first_name" : {
		      "encrypt" : {
			  "bsonType" : "string",
			  "algorithm" : "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
			}
		    },
		    "last_name" : {
		      "encrypt" : {
		        "bsonType" : "string",
			  "algorithm" : "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
			}
		    },
		    "othernames" : {
		      "encrypt" : {
		        "bsonType" : "string",
			}
		    }
	       }
	   },
         "address" : {
           "bsonType" : "object",
           "properties" : {
             "streetAddress" : {
               "encrypt" : {
                 "bsonType" : "string"
               }
             },
             "suburbCounty" : {
               "encrypt" : {
                 "bsonType" : "string"
               }
             }
           }
         },
         "phoneNumber" : {
           "encrypt" : {
             "bsonType" : "string"
           }
         },
         "salary" : {
           "encrypt" : {
             "bsonType" : "object"
           }
         },
         "taxIdentifier" : {
           "encrypt" : {
             "bsonType" : "string"
           }
         }
       }
     }
   }
 }
)


# Inspect the schema

db.getCollectionInfos( { name: "employee" } )[0].options.validator






# 6. Run python driver script with encryption enabled

virtualenv .

bin/pip install boto3
bin/pip install pymongo
bin/python -m bin/pip install 'pymongo[encryption]'

bin/python main.py
