from flask import Flask, jsonify, request
from pymongo import MongoClient
from flask_restful import Resource, Api
import bcrypt, spacy

app = Flask(__name__)

api = Api(app)


client = MongoClient('mongodb://db:27017')
mydb = client.myDB

userStore = mydb['userStore']

def verify_user(username, password):
    hashed_pw = userStore.find(
        {
            'username': username
        },
        {
            #'username': 0,
            'password': 1,
            #'tokenCount': 0,
        }
    )

    if hashed_pw.count() == 0:
        return False

    hashed_pw = hashed_pw[0]['password']

    if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
        return True
    else:
        return False

def updateTokenCount(username):
    
    tokenCount = userStore.find(
        {
            'username': username
        },
        {
            'tokenCount': 1
        }
    )

    if tokenCount.count() == 0:
        return False
    
    tokenCount = tokenCount[0]['tokenCount']
    
    if int(tokenCount) == 0:
        return False
    
    tokenCount = int(tokenCount) - 1

    userStore.update(
        {
            'username': username
        },

        {'$set': {
            'tokenCount': tokenCount
        }}
    )

    return True

class Register(Resource):
    def post(self):

        data = request.get_json()

        # check if data is valid, otherwise return error
        try:
            username = data['username']
            password = data['password']
        except Exception as e:
            print(e)

            return jsonify(
                {
                    'status': 301,
                    'msg': 'Improper username and password '+str(e)
                }
            )

        if not (username and password and len(username.strip()) > 1 and len(password.strip()) > 1):
            return jsonify(
                {
                    'status': 301,
                    'msg': 'not proper username and password format username: '+str(username) + ' password: '+ str(password)
                }
            )

        # just making sure username and password are properly clean 
        # before proceeding 
        username = username.strip()
        password = password.strip()

        # check if user does not already exist
        userObj =  userStore.find(
            {
                'username': username
            },
            {
                'username': 1
            }
        )

        if not (userObj.count() == 0):
            return jsonify(
                {
                    'status': 301,
                    'msg': 'User already present'
                }
            )

        # prepare the username and password for store

        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf8'), salt)

        userStore.insert(
            {
                'username': username,
                'password': hashed,
                'tokenCount': 10
            }
        )

        return jsonify(
            {
                'status': 200,
                'msg': 'Record Created'
            }
        )
        
class Compare(Resource):
    def post(self):

        data = request.get_json()

        # check if data is valid, otherwise return error
        try:
            username = data['username']
            password = data['password']
            text1 = data['text1']
            text2 = data['text2']
        except:
            return jsonify(
                {
                    'status': 301,
                    'msg': 'Improper username and password or text pair'
                }
            )

        if not (username and password and text1 and text2 and len(username.strip()) > 1 
                    and len(password.strip()) > 1 and len(text1.strip()) > 1) and len(text2.strip()):
            return jsonify(
                {
                    'status': 301,
                    'msg': 'not proper username and password format username: '
                    +str(username) + ' password: '+ str(password) + ' text1 : '+
                    str(text1) + ' text2: ' + str(text2)
                }
            )

        username = username.strip()
        password = password.strip()
        text1 = text1.strip()
        text2 = text2.strip()

        checkFlg = verify_user(username, password)

        if checkFlg:
            
            flg_ = updateTokenCount(username)

            if not flg_:
                return jsonify(
                    {
                        'status': 301,
                        'msg': 'Not Enough Tokens'
                    }
                )

            # all checks complete nopw process the text comparison

            nlp = spacy.load('en_core_web_sm')
            text1 = nlp(text1)
            text2 = nlp(text2)

            ratio = text1.similarity(text2)
            text1_sent = text1.sentiment
            text2_sent = text2.sentiment


            return jsonify(
                {
                    'status': 200,
                    'similarity_ratio': ratio,
                    'text1_sentiment': text1_sent,
                    'text2_sentiment': text2_sent
                }
            )

class RefillTokens(Resource):
    def post(self):
        data = request.get_json()

        # check if data is valid, otherwise return error
        try:
            username = data['username']
            password = data['password']
            targetUser = data['targetUser']
            refill = data['refill']

            refill = int(refill.strip())
        except Exception as e:
            print(e)

            return jsonify(
                {
                    'status': 301,
                    'msg': 'Improper username, password, targetUser or refill '+str(e)
                }
            )

        if not (username and password and refill and targetUser and
                 len(username.strip()) > 1 and len(password.strip()) > 1 and
                  len(targetUser) > 1):
            return jsonify(
                {
                    'status': 301,
                    'msg': 'not proper username and password format username: '+
                    str(username) + ' password: '+ str(password) + ' refill: '+ str(refill)
                }
            )

        # just making sure username and password are properly clean 
        # before proceeding 
        username = username.strip()
        password = password.strip()
        targetUser = targetUser.strip()

        if not (username == 'AdminUser' and password == 'AdminPass'):
            return jsonify(
                {
                    'status': 301,
                    'msg': 'the admin acuthentication failed'
                }
            )

        # check if targetuser is present

        userObj = userStore.find(
            {
                'username': targetUser
            },
            {
                'username': 1
            }
        )

        if userObj.count() == 0:
            return jsonify(
                {
                    'status': 301,
                    'msg': 'targetUser Does not Exist'
                }
            )

        # process the targetUser token refill since all checked are done

        userStore.update(
            {'username': targetUser},
            {
                '$set':{
                    'tokenCount': int(refill)
                }
            }
        )

        return jsonify(
            {
                'status': 200,
                'msg': 'the user: '+str(targetUser) + ' is refilled with: '+
                    str(refill) + ' tokens'
            }
        )



api.add_resource(Register, '/register')
api.add_resource(Compare, '/compare')
api.add_resource(RefillTokens, '/refill')



if __name__ == '__main__':
    app.run(host='0.0.0.0', port='5000')

