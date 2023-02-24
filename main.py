try:
    import boto3
    import datetime
    import pymongo
    import random
    import sys
    from botocore.exceptions import ClientError
    from pymongo.errors import EncryptionError, DuplicateKeyError
    from bson.codec_options import CodecOptions
    from pymongo.encryption import Algorithm
    from bson.binary import STANDARD
    from pymongo.encryption import ClientEncryption
except ImportError as e:
    print(e)
    exit(1)


def mdb_client(db_data):
    try:
        client = pymongo.MongoClient('mongodb+srv://', 
                    username='',
                    password='',
                    authSource='admin',
                    authMechanism='SCRAM-SHA-1',
                    ssl='true',
                    connect=False)
        client.admin.command('hello')
        return client, None
    except (pymongo.errors.ServerSelectionTimeoutError, pymongo.errors.ConnectionFailure) as e:
        return None, "Cannot connect to database, please check settings in config file: %s" % e


def decryptPayload(en_client, data):
    try:
        val = en_client.decrypt(data['name']['first_name'])
        data['name']['first_name'] = val

        val = en_client.decrypt(data['name']['last_name'])
        data['name']['last_name'] = val

        val = en_client.decrypt(data['name']['othernames'])
        data['name']['othernames'] = val

        val = en_client.decrypt(data['address']['streetAddress'])
        data['address']['streetAddress'] = val

        val = en_client.decrypt(data['address']['suburbCounty'])
        data['address']['suburbCounty'] = val

        val = en_client.decrypt(data['phoneNumber'])
        data['phoneNumber'] = val

        val = en_client.decrypt(data['salary'])
        data['salary'] = val

        val = en_client.decrypt(data['taxIdentifier'])
        data['taxIdentifier'] = val


    except EncryptionError as e:
        return None, e
    return data, None


# We are encrypting only firstName add methods to do this based on our requirements.
def encryptPayload(en_client, data, dek):
    try:
        val = en_client.encrypt(data['name']['first_name'], Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic, dek)
        data['name']['first_name'] = val

        val = en_client.encrypt(data['name']['last_name'], Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic, dek)
        data['name']['last_name'] = val

        val = en_client.encrypt(data['name']['othernames'], Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random, dek)
        data['name']['othernames'] = val

        val = en_client.encrypt(data['address']['streetAddress'], Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random, dek)
        data['address']['streetAddress'] = val

        val = en_client.encrypt(data['address']['suburbCounty'], Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random, dek)
        data['address']['suburbCounty'] = val

        val = en_client.encrypt(data['phoneNumber'], Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random, dek)
        data['phoneNumber'] = val

        val = en_client.encrypt(data['salary'], Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random, dek)
        data['salary'] = val

        val = en_client.encrypt(data['taxIdentifier'], Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random, dek)
        data['taxIdentifier'] = val

    except EncryptionError as e:
        return None, e
    return data, None


def getAWSToken():
    try:
        sts_client = boto3.client('sts')
        # Call the assume_role method of the STSConnection object and pass the role
        # ARN and a role session name.
        # Obviously this should not be hardcoded
        assumed_role_object = sts_client.assume_role(
            RoleArn="",
            RoleSessionName="applicationSession",
            DurationSeconds=3600
        )
        return assumed_role_object['Credentials'], None
    except ClientError as e:
        return None, e


def main():
    # Obviously this should not be hardcoded
    config_data = {
        "DB_CONNECTION_STRING": "mongodb+srv://",
        "DB_TIMEOUT": 5000,
        "DB_SSL": True
    }

    keyvault_namespace = "__encryption.__keyVault"
    provider = "aws"
    assumed_role_object, err = getAWSToken()
    if err != None:
        print(f"AWS Token error: {err}")
        sys.exit(1)

    kms_provider = {
        provider: {
            "accessKeyId": assumed_role_object['AccessKeyId'],
            "secretAccessKey": assumed_role_object['SecretAccessKey'],
            "sessionToken": assumed_role_object['SessionToken']
        }
    }

    encrypted_db_name = "companyData"
    encrypted_coll_name = "employee"

    client, err = mdb_client(config_data)
    if err != None:
        print(f"MongoDB Client error: {err}")
        sys.exit(1)

    client_encryption = ClientEncryption(
        kms_provider,
        keyvault_namespace,
        client,
        CodecOptions(uuid_representation=STANDARD)
    )

    # retrieve the DEK UUID
    data_key_id_1 = client["__encryption"]["__keyVault"].find_one({"keyAltNames": "dataKey1"}, {"_id": 1})['_id']

    # Create our payload with encrypted values
    # Complete this
    payload = {
        "_id": 2323, # employee ID
        "name": {
            "first_name": "Will",
            "last_name": "T",
            "othernames": "null",
        },
        "address": {
            "streetAddress": "537 White Hills Rd",
            "suburbCounty": "Evandale",
            "zipPostcode": "7258",
            "stateProvince": "Tasmania",
            "country": "Oz"
        },
        "dob": "1989-01-01T00:00:00.000Z",
        "phoneNumber": "+61 400 000 111",
        "salary": {
            "current": 99000.00,
            "startDate": "2022-06-01T00:00:00.000Z",
            "history": [
            {
                "salary": 89000.00,
                "startDate": "2021-08-11T00:00:00.000Z"
            }
            ]
        },
        "taxIdentifier": "103-443-923",
        "role": [
            "IC"
        ]
        }


    # remove `name.othernames` if None because wwe cannot encrypt none
    # Complete this

    # encrypt parts of the payload that require encrypting
    payload, err = encryptPayload(client_encryption, payload, data_key_id_1)

    if err != None:
        print(f"Encryption error: {err}")
        sys.exit(1)

    # insert our document
    try:
        result = client[encrypted_db_name][encrypted_coll_name].insert_one(payload)
        inserted_id = result.inserted_id
    except DuplicateKeyError as e:
        print("duplicate")
        inserted_id = payload["_id"]

    print(inserted_id)
    encrypted_result = client[encrypted_db_name][encrypted_coll_name].find_one({"_id": inserted_id})

    if encrypted_result:
        result, err = decryptPayload(client_encryption, encrypted_result)
        if err != None:
            print(f"Decrypt error: {err}")
            sys.exit(1)
        print(result)


if __name__ == "__main__":
    main()
