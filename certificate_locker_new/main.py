from flask import Flask
from flask import Flask, render_template, Response, redirect, request, session, abort, url_for
import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from PIL import Image
from flask_mail import Mail, Message
from datetime import datetime
from datetime import date
import datetime
import random
from random import seed
from random import randint
import json
import pandas as pd

import pytesseract

import numpy as np
from matplotlib import pyplot as plt
import cv2
import imagehash
from PIL import Image, ImageDraw, ImageFilter
from skimage.metrics import structural_similarity
import PIL.Image
from PIL import Image
from PIL import Image, ImageFilter, ImageDraw, ImageStat



from werkzeug.utils import secure_filename
from flask import send_file
import numpy as np
import threading
import time
import shutil
import hashlib
import urllib.request
import urllib.parse
from urllib.request import urlopen
import webbrowser
import mysql.connector
from Crypto import Random
from Crypto.Cipher import AES

mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  passwd="",
  charset="utf8",
  database="certificate_locker_new"
)


app = Flask(__name__)
##session key
app.secret_key = 'abcdef'
UPLOAD_FOLDER = 'static/upload'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
#####
##email
mail_settings = {
    "MAIL_SERVER": 'smtp.gmail.com',
    "MAIL_PORT": 465,
    "MAIL_USE_TLS": False,
    "MAIL_USE_SSL": True,
    "MAIL_USERNAME": "stegofaceidissuer@gmail.com",
    "MAIL_PASSWORD": "pwxzxzkmnyygrakr"
}

app.config.update(mail_settings)
mail = Mail(app)
#######
class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]
####
    
@app.route('/',methods=['POST','GET'])
def index():
    cnt=0
    act=""
    msg=""

    
    
    if request.method == 'POST':
        username1 = request.form['uname']
        password1 = request.form['pass']
        mycursor = mydb.cursor()
        mycursor.execute("SELECT count(*) FROM nt_register where uname=%s && pass=%s",(username1,password1))
        myresult = mycursor.fetchone()[0]
        if myresult>0:
            session['username'] = username1
            result=" Your Logged in sucessfully**"
            return redirect(url_for('userhome')) 
        else:
            msg="Invalid Username or Password!"
            result="Your logged in fail!!!"
        

    return render_template('index.html',msg=msg,act=act)

@app.route('/login',methods=['POST','GET'])
def login():
    cnt=0
    act=""
    msg=""
    if request.method == 'POST':
        
        username1 = request.form['uname']
        password1 = request.form['pass']
        mycursor = mydb.cursor()
        mycursor.execute("SELECT count(*) FROM nt_login where username=%s && password=%s",(username1,password1))
        myresult = mycursor.fetchone()[0]
        if myresult>0:
            session['username'] = username1
            #result=" Your Logged in sucessfully**"
            return redirect(url_for('admin')) 
        else:
            msg="Your logged in fail!!!"
        

    return render_template('login.html',msg=msg,act=act)


@app.route('/login_cca',methods=['POST','GET'])
def login_cca():
    cnt=0
    act=""
    msg=""
    if request.method == 'POST':
        
        username1 = request.form['uname']
        password1 = request.form['pass']
        mycursor = mydb.cursor()
        mycursor.execute("SELECT count(*) FROM nt_cca where uname=%s && pass=%s && status=1",(username1,password1))
        myresult = mycursor.fetchone()[0]
        if myresult>0:
            session['username'] = username1
            #result=" Your Logged in sucessfully**"
            return redirect(url_for('home_cca')) 
        else:
            msg="Incorrect Username/Password or wait for approval"
        

    return render_template('login_cca.html',msg=msg,act=act)

@app.route('/login_issuer',methods=['POST','GET'])
def login_issuer():
    cnt=0
    act=""
    msg=""
    if request.method == 'POST':
        
        username1 = request.form['uname']
        password1 = request.form['pass']
        mycursor = mydb.cursor()
        mycursor.execute("SELECT count(*) FROM nt_issuer where uname=%s && pass=%s && status=1",(username1,password1))
        myresult = mycursor.fetchone()[0]
        if myresult>0:
            session['username'] = username1
            #result=" Your Logged in sucessfully**"
            return redirect(url_for('issuer_home')) 
        else:
            msg="Incorrect Username/Password or wait for approval"
        

    return render_template('login_issuer.html',msg=msg,act=act)


###
#Blockchain
class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set()

        # Create the genesis block
        self.new_block(previous_hash='1', proof=100)

    def register_node(self, address):
        """
        Add a new node to the list of nodes

        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """

        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')


    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid

        :param chain: A blockchain
        :return: True if valid, False if not
        """

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.

        :return: True if our chain was replaced, False if not
        """

        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

    def new_block(self, proof, previous_hash):
        """
        Create a new Block in the Blockchain

        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reset the current list of transactions
        self.current_transactions = []

        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount):
        """
        Creates a new transaction to go into the next mined Block

        :param sender: Address of the Sender
        :param recipient: Address of the Recipient
        :param amount: Amount
        :return: The index of the Block that will hold this transaction
        """
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })

        return self.last_block['index'] + 1

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block

        :param block: Block
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block):
        """
        Simple Proof of Work Algorithm:

         - Find a number p' such that hash(pp') contains leading 4 zeroes
         - Where p is the previous proof, and p' is the new proof
         
        :param last_block: <dict> last Block
        :return: <int>
        """

        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        """
        Validates the Proof

        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :param last_hash: <str> The hash of the Previous Block
        :return: <bool> True if correct, False if not.

        """

        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)

    # We must receive a reward for finding the proof.
    # The sender is "0" to signify that this node has mined a new coin.
    blockchain.new_transaction(
        sender="0",
        recipient=node_identifier,
        amount=1,
    )

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)

    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200


def new_transaction():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['sender', 'recipient', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Create a new Transaction
    index = blockchain.new_transaction(values['sender'], values['recipient'], values['amount'])

    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201

def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200



def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201

def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200

def certificatechain(uid,uname,bcdata,utype):
    ############

    now = datetime.datetime.now()
    yr=now.strftime("%Y")
    mon=now.strftime("%m")
    rdate=now.strftime("%d-%m-%Y")
    rtime=now.strftime("%H:%M:%S")
    
    ff=open("static/key.txt","r")
    k=ff.read()
    ff.close()
    
    #bcdata="CID:"+uname+",Time:"+val1+",Unit:"+val2
    dtime=rdate+","+rtime

    ky=uname
    obj=AESCipher(ky)

    
    benc=obj.encrypt(bcdata)
    benc1=benc.decode("utf-8")

    ff1=open("static/js/d1.txt","r")
    bc1=ff1.read()
    ff1.close()
    
    px=""
    if k=="1":
        px=""
        result = hashlib.md5(bcdata.encode())
        key=result.hexdigest()
        print(key)
        v=k+"##"+key+"##"+bcdata+"##"+dtime

        ff1=open("static/js/d1.txt","w")
        ff1.write(v)
        ff1.close()
        
        dictionary = {
            "ID": "1",
            "Pre-hash": "00000000000000000000000000000000",
            "Hash": key,
            "utype": utype,
            "Date/Time": dtime
        }

        k1=int(k)
        k2=k1+1
        k3=str(k2)
        ff1=open("static/key.txt","w")
        ff1.write(k3)
        ff1.close()

        ff1=open("static/prehash.txt","w")
        ff1.write(key)
        ff1.close()
        
    else:
        px=","
        pre_k=""
        k1=int(k)
        k2=k1-1
        k4=str(k2)

        ff1=open("static/prehash.txt","r")
        pre_hash=ff1.read()
        ff1.close()
        
        g1=bc1.split("#|")
        for g2 in g1:
            g3=g2.split("##")
            if k4==g3[0]:
                pre_k=g3[1]
                break

        
        result = hashlib.md5(bcdata.encode())
        key=result.hexdigest()
        

        v="#|"+k+"##"+key+"##"+bcdata+"##"+dtime

        k3=str(k2)
        ff1=open("static/key.txt","w")
        ff1.write(k3)
        ff1.close()

        ff1=open("static/js/d1.txt","a")
        ff1.write(v)
        ff1.close()

        
        
        dictionary = {
            "ID": k,
            "Pre-hash": pre_hash,
            "Hash": key,
            "utype:": utype,
            "Date/Time": dtime
        }
        k21=int(k)+1
        k3=str(k21)
        ff1=open("static/key.txt","w")
        ff1.write(k3)
        ff1.close()

        ff1=open("static/prehash.txt","w")
        ff1.write(key)
        ff1.close()

    m=""
    if k=="1":
        m="w"
    else:
        m="a"
    # Serializing json
    
    json_object = json.dumps(dictionary, indent=4)
     
    # Writing to sample.json
    with open("static/certificatechain.json", m) as outfile:
        outfile.write(json_object)
    ##########

@app.route('/register',methods=['POST','GET'])
def register():
    result=""
    act=request.args.get('sid')
    mycursor = mydb.cursor()
    
 
    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
    yr=now.strftime("%Y")
    mycursor.execute("SELECT max(id)+1 FROM nt_register")
    maxid = mycursor.fetchone()[0]
    if maxid is None:
        maxid=1

    uid=str(maxid)
    rn2=randint(100,999)
    val=uid.zfill(3)
    yr1=yr[2:4]
    un="U"+yr1+str(rn2)+val
        
    if request.method=='POST':
        
        name=request.form['name']
        mobile=request.form['mobile']
        email=request.form['email']
        address=request.form['address']
        uname=request.form['uname']
        pass1=request.form['pass']

        
        
        mycursor = mydb.cursor()

        mycursor.execute("SELECT count(*) FROM nt_register where uname=%s",(uname, ))
        cnt = mycursor.fetchone()[0]
        if cnt==0:
            

            result = hashlib.md5(uname.encode())
            key=result.hexdigest()
            pbkey=key[0:8]
            prkey=key[8:16]
            
            sql = "INSERT INTO nt_register(id, name, mobile, email, address,  uname, pass,private_key,public_key) VALUES (%s, %s, %s, %s, %s, %s, %s,%s,%s)"
            val = (maxid, name, mobile, email, address, uname, pass1,pbkey,prkey)
            act="success"
            mycursor.execute(sql, val)
            mydb.commit()            
            #print(mycursor.rowcount, "record inserted.")

            bcdata="ID: "+str(maxid)+",Certificate Holder :"+name+", User ID:"+uname+",Register Date: "+rdate+""            
            certificatechain(str(maxid),uname,bcdata,'CH')
            
            ##BC##
            '''sdata="ID:"+str(maxid)+",Student:"+name+",RegNo.:"+regno+",Department:"+dept+",RegDate:"+rdate
            result = hashlib.md5(sdata.encode())
            key=result.hexdigest()

            mycursor1 = mydb.cursor()
            mycursor1.execute("SELECT max(id)+1 FROM sb_blockchain")
            maxid1 = mycursor1.fetchone()[0]
            if maxid1 is None:
                maxid1=1
                pkey="00000000000000000000000000000000"
            else:
                mid=maxid1-1
                mycursor1.execute('SELECT * FROM sb_blockchain where id=%s',(mid, ))
                pp = mycursor1.fetchone()
                pkey=pp[3]
            sql2 = "INSERT INTO sb_blockchain(id,block_id,pre_hash,hash_value,sdata) VALUES (%s, %s, %s, %s, %s)"
            val2 = (maxid1,maxid,pkey,key,sdata)
            mycursor1.execute(sql2, val2)
            mydb.commit()  ''' 
            ####
            act="success"
            #return redirect(url_for('index',act=act)) 
        else:
            act="wrong"
            result="Already Exist!"
    return render_template('register.html',act=act,un=un)

@app.route('/reg',methods=['POST','GET'])
def reg():
    result=""
    act=request.args.get('act')
    mycursor = mydb.cursor()
    
 
    
    if request.method=='POST':
        
        name=request.form['name']
        mobile=request.form['mobile']
        email=request.form['email']
        address=request.form['address']
        uname=request.form['uname']
        pass1=request.form['pass']
        

        
        now = datetime.datetime.now()
        rdate=now.strftime("%d-%m-%Y")
        mycursor = mydb.cursor()

        
        mycursor.execute("SELECT max(id)+1 FROM nt_cca")
        maxid = mycursor.fetchone()[0]
        if maxid is None:
            maxid=1

        
    
        sql = "INSERT INTO nt_cca(id, name, mobile,  email, address,  uname, pass) VALUES (%s, %s, %s, %s, %s, %s, %s)"
        val = (maxid, name, mobile, email, address, uname, pass1)
        act="success"
        mycursor.execute(sql, val)
        mydb.commit()            
        print(mycursor.rowcount, "record inserted.")
        
        act="success"
        return redirect(url_for('reg',act=act)) 

    
        
    return render_template('reg.html',act=act)


@app.route('/reg_issuer',methods=['POST','GET'])
def reg_issuer():
    result=""
    act=request.args.get('act')
    mycursor = mydb.cursor()
    
 
    
    if request.method=='POST':
        
        name=request.form['name']
        mobile=request.form['mobile']
        email=request.form['email']
        address=request.form['address']
        uname=request.form['uname']
        pass1=request.form['pass']
        

        
        now = datetime.datetime.now()
        rdate=now.strftime("%d-%m-%Y")
        mycursor = mydb.cursor()

        
        mycursor.execute("SELECT max(id)+1 FROM nt_issuer")
        maxid = mycursor.fetchone()[0]
        if maxid is None:
            maxid=1

        
    
        sql = "INSERT INTO nt_issuer(id, name, mobile, email, address,  uname, pass) VALUES (%s, %s, %s, %s, %s, %s, %s)"
        val = (maxid, name, mobile, email, address, uname, pass1)
        act="success"
        mycursor.execute(sql, val)
        mydb.commit()            
        print(mycursor.rowcount, "record inserted.")
        
        act="success"
        return redirect(url_for('reg_issuer',act=act)) 

    
        
    return render_template('reg_issuer.html',act=act)

@app.route('/admin',methods=['POST','GET'])
def admin():
    result=""
    
    mycursor = mydb.cursor()
    
    act=request.args.get("act") 
   
    mycursor.execute("SELECT * FROM nt_cca")
    data = mycursor.fetchall()

    if act=="yes":
        rid=request.args.get("rid")
        mycursor.execute("update nt_cca set status=1 where id=%s",(rid,))
        mydb.commit()
        return redirect(url_for('admin'))

    if act=="del":
        did=request.args.get("did")
        mycursor.execute("delete from nt_cca where id=%s",(did,))
        mydb.commit()
        return redirect(url_for('admin')) 
        
        
    return render_template('admin.html',act=act,data=data)

@app.route('/view_issuer',methods=['POST','GET'])
def view_issuer():
    result=""
    
    mycursor = mydb.cursor()
    
    act=request.args.get("act") 
   
    mycursor.execute("SELECT * FROM nt_issuer")
    data = mycursor.fetchall()

    if act=="yes":
        rid=request.args.get("rid")
        mycursor.execute("update nt_issuer set status=1 where id=%s",(rid,))
        mydb.commit()
        return redirect(url_for('admin'))

    if act=="del":
        did=request.args.get("did")
        mycursor.execute("delete from nt_issuer where id=%s",(did,))
        mydb.commit()
        return redirect(url_for('view_issuer')) 
        
        
    return render_template('view_issuer.html',act=act,data=data)

@app.route('/view_user',methods=['POST','GET'])
def view_user():
    result=""
    act=request.args.get("act") 
    mycursor = mydb.cursor()
    
    mycursor.execute("SELECT * FROM nt_register")
    data = mycursor.fetchall()

    if act=="del":
        did=request.args.get("did")
        mycursor.execute("delete from nt_register where id=%s",(did,))
        mydb.commit()
        return redirect(url_for('view_user'))

    
    return render_template('view_user.html',data=data)


@app.route('/userhome', methods=['GET', 'POST'])
def userhome():
    uname=""
    msg=""
    hashval=""
    filename=""
    fn=""
    cid=""
    canno=""
    act = request.args.get('act')
    if 'username' in session:
        uname = session['username']
    name=""
    message=""
    print(uname)
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM nt_register where uname=%s",(uname, ))
    value = mycursor.fetchone()
    prk=value[7]
    pbkey=value[8]
    name=value[1]
    email=value[3]
    

    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
    mm=now.strftime("%m")
    yy=now.strftime("%y")
    if request.method=='POST':
        canno=request.form['canno']
        detail=request.form['detail']

        mycursor.execute("SELECT count(*) FROM nt_certificate where uname=%s && canno=%s",(uname,canno ))
        cnt1 = mycursor.fetchone()[0]
                
        mycursor.execute("SELECT count(*) FROM nt_certificate_issued where kyc_code=%s",(canno, ))
        cnt3 = mycursor.fetchone()[0]
        if cnt3>0 and cnt1==0:
                
            mycursor.execute("SELECT max(id)+1 FROM nt_certificate")
            maxid = mycursor.fetchone()[0]
            if maxid is None:
                maxid=1
            cid=str(maxid)
            #cno="CN"+mm+yy+str(maxid)


            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)
            file = request.files['file']
            
            file_type = file.content_type
            # if user does not select file, browser also
            # submit an empty part without filename
            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)
            if file:
                #fname = "EF"+str(maxid)+file.filename
                #filename = secure_filename(fname)
                fname=file.filename
                filename="F"+str(maxid)+fname
                fn=filename
                file.save(os.path.join("static/upload", filename))
                shutil.copy("static/upload/"+filename,"static/d1/"+filename)
            ##########
            

            md5hash = hashlib.md5(Image.open("static/upload/"+filename).tobytes())
            #print(md5hash.hexdigest())
            hashval=md5hash.hexdigest()
                
            mycursor.execute("SELECT * FROM nt_certificate_issued where kyc_code=%s",(canno, ))
            data1 = mycursor.fetchone()
            hkey=data1[4]

            if hashval==hkey:
                st="yes"
            else:
                st="no"
            #########
            if st=="yes":
                
        
                #shutil.copy("static/upload/"+filename,"static/decrypted/"+filename)
                result = hashlib.md5(canno.encode())
                key=result.hexdigest()
                ckey=key[0:8]
                
                ##encryption
                password_provided = prk # This is input in the form of a string
                password = password_provided.encode() # Convert to type bytes
                salt = b'salt_' # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend()
                )
                key = base64.urlsafe_b64encode(kdf.derive(password))

                input_file = 'static/upload/'+filename
                output_file = 'static/upload/'+filename
                with open(input_file, 'rb') as f:
                    data = f.read()

                fernet = Fernet(key)
                encrypted = fernet.encrypt(data)

                with open(output_file, 'wb') as f:
                    f.write(encrypted)
                    
                
                message="Certificate Owner:"+uname+", UCIC Code:"+canno+""
                act="yes"
                ##store
                sql = "INSERT INTO nt_certificate(id,uname,ctype,filename,detail,rdate,canno,ckey) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
                val = (maxid,uname,'',filename,detail,rdate,canno,ckey)
                mycursor.execute(sql,val)
                mydb.commit()

                bcdata="ID: "+str(maxid)+",UCIC Code:"+canno+", Upload by "+uname+", Pre Hash:"+hkey+", Hash:"+hashval+", Matched"            
                certificatechain(str(maxid),uname,bcdata,'CU')
                msg="success"
                #else:
                #    msg="fail"
            else:
                fst=""
                ###
                try:
                    ##
                    # Detect the faces
                    image = cv2.imread("static/upload/"+filename)
                    face_cascade = cv2.CascadeClassifier('haarcascade_frontalface_default.xml')
                    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
                    faces = face_cascade.detectMultiScale(gray, 1.1, 4)
                    
                    # Draw the rectangle around each face
                    j = 1
                    for (x, y, w, h) in faces:
                        mm=cv2.rectangle(image, (x, y), (x+w, y+h), (255, 0, 0), 2)
                        rectface="R"+filename
                        cv2.imwrite("static/upload/"+rectface, mm)
                        image = cv2.imread("static/upload/"+rectface)
                        cropped = image[y:y+h, x:x+w]
                        gg="C"+filename
                        cv2.imwrite("static/upload/"+gg, cropped)
                        print("yes")
                        fst="yes"
                        j += 1

                except:
                    fst="no"
                
                pytesseract.pytesseract.tesseract_cmd = 'C:\\Program Files\\Tesseract-OCR\\tesseract.exe'
                ############
                Actual_image = cv2.imread("static/upload/"+filename)
                #Sample_img = cv2.resize(Actual_image,(400,350))
                Image_ht,Image_wd,Image_thickness = Actual_image.shape
                Sample_img = cv2.cvtColor(Actual_image,cv2.COLOR_BGR2RGB)
                texts = pytesseract.image_to_data(Sample_img) 
                mytext=""
                prevy=0

                
                
                for cnt,text in enumerate(texts.splitlines()):
                    
                    if cnt==0:
                        continue
                    text = text.split()
                    if len(text)==12:
                        x,y,w,h = int(text[6]),int(text[7]),int(text[8]),int(text[9])
                        if(len(mytext)==0):
                            prey=y
                        if(prevy-y>=10 or y-prevy>=10):
                            #print(mytext)
                            s=1
                            #mytext=""
                        mytext = mytext + text[11]+" "
                        prevy=y

                v11=mytext
                ############
                
                ############
                fs=0
                if fst=="yes":
                    fs=1
                bcdata="ID: "+str(maxid)+",UCIC Code:"+canno+", Tampered, Upload by "+uname+",Pre Hash:"+hkey+", Hash:"+hashval+", Not Match"            
                certificatechain(str(maxid),uname,bcdata,'CA')
                mycursor.execute("SELECT count(*) FROM nt_tamper where uname=%s",(uname,))
                cnt2 = mycursor.fetchone()[0]
                if cnt2==0:
                    
                    mycursor.execute("SELECT max(id)+1 FROM nt_tamper")
                    maxid = mycursor.fetchone()[0]
                    if maxid is None:
                        maxid=1
                    
                        
                    sql = "INSERT INTO nt_tamper(id,uname,canno,hash1,hash2,filename,face_status,text_value) VALUES (%s, %s, %s,%s,%s, %s, %s, %s)"
                    val = (maxid,uname,canno,hkey,hashval,filename,fs,v11)
                    mycursor.execute(sql,val)
                    mydb.commit()
                else:
                    mycursor.execute("update nt_tamper set canno=%s,hash1=%s,hash2=%s,filename=%s,face_status=%s,text_value=%s where uname=%s",(canno,hkey,hashval,filename,fs,v11,uname))
                    mydb.commit()
                msg="attack"
                ########
        else:
            msg="wrong"
        
    data=[]
    mycursor.execute("SELECT * FROM nt_certificate where uname=%s",(uname,))
    data = mycursor.fetchall()
    
    '''x=0
    for rd in data1:
        dt=[]
        x+=1
        dss=[]
        dt.append(rd[0])
        dt.append(rd[1])
        dt.append(rd[2])
        dt.append(rd[3])
        dt.append(rd[4])
        dt.append(rd[5])
        dt.append(rd[7])
        
        mycursor.execute("SELECT * FROM nt_require where cid=%s",(rd[0],))
        dd = mycursor.fetchall()
        for rd1 in dd:
            ds=[]
            ds.append(rd1[3])
            ds.append(rd1[4])
            dss.append(ds)
        dt.append(dss)
    data.append(dt)'''
            
    print(data)
    if act=="del":
        did = request.args.get('did')
        mycursor.execute("delete from nt_certificate where id=%s", (did,))
        mydb.commit()
        return redirect(url_for('userhome'))

    if act=="re":
        cid = request.args.get('cid')
        mycursor.execute("update nt_certificate set c_status=0 where id=%s", (cid,))
        mydb.commit()
        return redirect(url_for('userhome',act='rev'))
    
    
    return render_template('userhome.html',value=value,msg=msg,data=data,act=act,email=email,message=message,cid=cid,fn=fn,canno=canno)

@app.route('/user_view', methods=['GET', 'POST'])
def user_view():
    uname=""
    uu=""
    msg=""
    hashval=""
    hash1=""
    st=""
    filename=""
    cid= request.args.get('cid')
    canno= request.args.get('canno')
    fn= request.args.get('fn')
    act = request.args.get('act')
    if 'username' in session:
        uname = session['username']
    name=""
    message=""
    
    mycursor = mydb.cursor()

    #mycursor.execute("SELECT * FROM nt_certificate where id=%s",(cid, ))
    #data = mycursor.fetchone()
    #canno=data[7]
    #fn=data[3]
    
    md5hash = hashlib.md5(Image.open("static/d1/"+fn).tobytes())
    hash1=md5hash.hexdigest()
            
    
    
    mycursor.execute("SELECT * FROM nt_certificate_issued where kyc_code=%s",(canno, ))
    data1 = mycursor.fetchone()
    hash2=data1[4]

    if hash1==hash2:
        st="yes"

    else:
        st="no"
        

    return render_template('user_view.html',msg=msg,data1=data1,cid=cid,act=act,hash1=hash1,st=st,fn=fn,canno=canno)

@app.route('/user_view2', methods=['GET', 'POST'])
def user_view2():
    uname=""
    uu=""
    msg=""
    hashval=""
    hash1=""
    st=""
    filename=""
    cid= request.args.get('cid')
    fn= request.args.get('fn')
    uu = request.args.get('uu')
    act = request.args.get('act')
    if 'username' in session:
        uname = session['username']
    name=""
    message=""
    
    mycursor = mydb.cursor()

    mycursor.execute("SELECT * FROM nt_certificate where id=%s",(cid, ))
    data = mycursor.fetchone()
    canno=data[7]
   
    md5hash = hashlib.md5(Image.open("static/test/"+fn).tobytes())
    hash1=md5hash.hexdigest()
            
    
    
    mycursor.execute("SELECT * FROM nt_certificate_issued where kyc_code=%s",(canno, ))
    data1 = mycursor.fetchone()
    hash2=data1[4]

    if hash1==hash2:
        st="yes"

    else:
        st="no"
        

    return render_template('user_view2.html',msg=msg,data=data,data1=data1,cid=cid,act=act,hash1=hash1,st=st,uu=uu,fn=fn)

@app.route('/user_view3', methods=['GET', 'POST'])
def user_view3():
    uname=""
    uu=""
    msg=""
    hashval=""
    hash1=""
    st=""
    filename=""
    cid= request.args.get('cid')
    act = request.args.get('act')
    if 'username' in session:
        uname = session['username']
    name=""
    message=""
    
    mycursor = mydb.cursor()

    mycursor.execute("SELECT * FROM nt_certificate where id=%s",(cid, ))
    data = mycursor.fetchone()
    canno=data[7]
    fn=data[3]
    uu=data[1]
    
    md5hash = hashlib.md5(Image.open("static/d1/"+fn).tobytes())
    hash1=md5hash.hexdigest()
            
    
    
    mycursor.execute("SELECT * FROM nt_certificate_issued where kyc_code=%s",(canno, ))
    data1 = mycursor.fetchone()
    hash2=data1[4]

    if hash1==hash2:
        st="yes"

    else:
        st="no"
        

    return render_template('user_view3.html',msg=msg,data=data,data1=data1,cid=cid,act=act,hash1=hash1,st=st,uu=uu)

  
@app.route('/send_req2', methods=['GET', 'POST'])
def send_req2():
    uname=""
    uu=""
    msg=""
    hashval=""
    filename=""
    fn=""
    cid=""
    act = request.args.get('act')
    if 'username' in session:
        uname = session['username']
    name=""
    message=""
    
    mycursor = mydb.cursor()

    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
    mm=now.strftime("%m")
    yy=now.strftime("%y")
    if request.method=='POST':
        canno=request.form['canno']
        

        mycursor.execute("SELECT count(*) FROM nt_certificate_issued where kyc_code=%s",(canno, ))
        cnt3 = mycursor.fetchone()[0]
        if cnt3>0:
                
            mycursor.execute("SELECT max(id)+1 FROM nt_certificate")
            maxid = mycursor.fetchone()[0]
            if maxid is None:
                maxid=1

            mycursor.execute("SELECT * FROM nt_certificate where canno=%s",(canno, ))
            ccr = mycursor.fetchall()
            for ccr1 in ccr:
                cid=str(ccr1[0])

            file = request.files['file']
            
           
            if file:
                #fname = "EF"+str(maxid)+file.filename
                #filename = secure_filename(fname)
                fname=file.filename
                filename="F"+str(maxid)+fname
                fn=filename
                file.save(os.path.join("static/test", filename))
            ##########
            

            md5hash = hashlib.md5(Image.open("static/test/"+filename).tobytes())
            #print(md5hash.hexdigest())
            hashval=md5hash.hexdigest()
                
            mycursor.execute("SELECT * FROM nt_certificate_issued where kyc_code=%s",(canno, ))
            data1 = mycursor.fetchone()
            hkey=data1[4]

            if hashval==hkey:
                st="yes"
            else:
                st="no"
            #########
            
            if st=="yes":
                mycursor.execute("SELECT count(*) FROM nt_certificate where canno=%s",(canno, ))
                cnt1 = mycursor.fetchone()[0]

                mycursor.execute("update nt_certificate set c_status=1 where canno=%s",(canno,))
                mydb.commit()
                

                
                mycursor.execute("SELECT * FROM nt_certificate where canno=%s",(canno, ))
                udat = mycursor.fetchall()
                for udat1 in udat:
                    cid=str(udat1[0])
                    uu=udat1[5]

                bcdata="ID: "+str(cid)+",UCIC Code:"+canno+", Verify by "+uname+", Pre Hash:"+hkey+", Hash:"+hashval+", Matched"            
                certificatechain(str(cid),uname,bcdata,'CV')
                msg="success"
                
            else:
                fst=""
                ###
                mycursor.execute("SELECT * FROM nt_certificate where canno=%s",(canno, ))
                udat1 = mycursor.fetchall()
                for udat11 in udat1:
                    cid=udat11[0]
                    uu=udat11[1]
                print("uu===="+uu)
                try:
                    ##
                    # Detect the faces
                    image = cv2.imread("static/test/"+filename)
                    face_cascade = cv2.CascadeClassifier('haarcascade_frontalface_default.xml')
                    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
                    faces = face_cascade.detectMultiScale(gray, 1.1, 4)
                    
                    # Draw the rectangle around each face
                    j = 1
                    for (x, y, w, h) in faces:
                        mm=cv2.rectangle(image, (x, y), (x+w, y+h), (255, 0, 0), 2)
                        rectface="R"+filename
                        cv2.imwrite("static/test/"+rectface, mm)
                        image = cv2.imread("static/test/"+rectface)
                        cropped = image[y:y+h, x:x+w]
                        gg="C"+filename
                        cv2.imwrite("static/test/"+gg, cropped)
                        print("yes")
                        fst="yes"
                        j += 1

                except:
                    fst="no"
                
                pytesseract.pytesseract.tesseract_cmd = 'C:\\Program Files\\Tesseract-OCR\\tesseract.exe'
                ############
                Actual_image = cv2.imread("static/test/"+filename)
                #Sample_img = cv2.resize(Actual_image,(400,350))
                Image_ht,Image_wd,Image_thickness = Actual_image.shape
                Sample_img = cv2.cvtColor(Actual_image,cv2.COLOR_BGR2RGB)
                texts = pytesseract.image_to_data(Sample_img) 
                mytext=""
                prevy=0

                
                
                for cnt,text in enumerate(texts.splitlines()):
                    
                    if cnt==0:
                        continue
                    text = text.split()
                    if len(text)==12:
                        x,y,w,h = int(text[6]),int(text[7]),int(text[8]),int(text[9])
                        if(len(mytext)==0):
                            prey=y
                        if(prevy-y>=10 or y-prevy>=10):
                            #print(mytext)
                            s=1
                            #mytext=""
                        mytext = mytext + text[11]+" "
                        prevy=y

                v11=mytext
                
                ############
                fs=0
                if fst=="yes":
                    fs=1
                bcdata="ID: "+str(maxid)+",UCIC Code:"+canno+", Tampered, Verify by "+uname+",Pre Hash:"+hkey+", Hash:"+hashval+", Not Match"            
                certificatechain(str(maxid),uname,bcdata,'CV')
                mycursor.execute("SELECT count(*) FROM nt_tamper where uname=%s",(uu,))
                cnt2 = mycursor.fetchone()[0]
                if cnt2==0:
                    
                    mycursor.execute("SELECT max(id)+1 FROM nt_tamper")
                    maxid = mycursor.fetchone()[0]
                    if maxid is None:
                        maxid=1
                    
                        
                    sql = "INSERT INTO nt_tamper(id,uname,canno,hash1,hash2,filename,face_status,text_value) VALUES (%s, %s, %s,%s,%s, %s, %s, %s)"
                    val = (maxid,uu,canno,hkey,hashval,filename,fs,v11)
                    mycursor.execute(sql,val)
                    mydb.commit()
                else:
                    mycursor.execute("update nt_tamper set canno=%s,hash1=%s,hash2=%s,filename=%s,face_status=%s,text_value=%s where uname=%s",(canno,hkey,hashval,filename,fs,v11,uu))
                    mydb.commit()
                msg="attack"
                ########
        else:
            msg="wrong"
        

    
    
    return render_template('send_req2.html',msg=msg,act=act,cid=cid,uu=uu,fn=fn)

@app.route('/tamper', methods=['GET', 'POST'])
def tamper():
    uname=""
    msg=""
    hashval=""
    filename=""
    fstatus=""
    dat3=[]
    act = request.args.get('act')
    if 'username' in session:
        uname = session['username']


    name=""
    message=""
    print(uname)
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM nt_register where uname=%s",(uname, ))
    value = mycursor.fetchone()

    mycursor.execute("SELECT * FROM nt_tamper where uname=%s",(uname, ))
    data = mycursor.fetchone()
    canno=data[2]

    mycursor.execute("SELECT * FROM nt_certificate_issued where kyc_code=%s",(canno, ))
    data1 = mycursor.fetchone()


    
    ############
    '''if data[6]==1:
        #resize
        try:
            img = cv2.imread('static/data/C'+data1[2])
            rez = cv2.resize(img, (100, 100))
            cv2.imwrite("static/test/t1.jpg", rez)

            img = cv2.imread('static/upload/C'+data[5])
            rez = cv2.resize(img, (100, 100))
            cv2.imwrite("static/test/t2.jpg", rez)
        
            cutoff=1
            hash0 = imagehash.average_hash(Image.open("static/test/t1.jpg")) 
            hash1 = imagehash.average_hash(Image.open("static/test/t2.jpg"))
            cc1=hash1 - hash0
            print("cc="+str(cc1))
            if cc1<=cutoff:
                fstatus="1"
            else:
                fstatus="2"
        except:
            print("try")'''

    ############
    txt1=data1[6]
    txt2=data[7]

    dat1=txt1.split("|")
    dat2=txt2.split("|")

    l2=len(dat2)
    
    i=0
    for nn in dat1:
        dt=[]
        if i<l2:
            if nn==dat2[i]:
                dt.append(dat2[i])
                dt.append("1")
            else:
                dt.append(dat2[i])
                dt.append("2")
            dat3.append(dt)
        i+=1

    ###################
    before = cv2.imread('static/data/'+data1[2])
    after = cv2.imread('static/upload/'+data[5])

    # Convert images to grayscale
    before_gray = cv2.cvtColor(before, cv2.COLOR_BGR2GRAY)
    after_gray = cv2.cvtColor(after, cv2.COLOR_BGR2GRAY)

    # Compute SSIM between the two images
    (score, diff) = structural_similarity(before_gray, after_gray, full=True)
    print("Image Similarity: {:.4f}%".format(score * 100))
    per=format(score * 100)

    # The diff image contains the actual image differences between the two images
    # and is represented as a floating point data type in the range [0,1] 
    # so we must convert the array to 8-bit unsigned integers in the range
    # [0,255] before we can use it with OpenCV
    diff = (diff * 255).astype("uint8")
    diff_box = cv2.merge([diff, diff, diff])

    # Threshold the difference image, followed by finding contours to
    # obtain the regions of the two input images that differ
    thresh = cv2.threshold(diff, 0, 255, cv2.THRESH_BINARY_INV | cv2.THRESH_OTSU)[1]
    contours = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    contours = contours[0] if len(contours) == 2 else contours[1]

    mask = np.zeros(before.shape, dtype='uint8')
    filled_after = after.copy()
    j=1
    for c in contours:
        area = cv2.contourArea(c)
        if area > 40:
            x,y,w,h = cv2.boundingRect(c)
            cv2.rectangle(before, (x, y), (x + w, y + h), (36,255,12), 2)
            mm=cv2.rectangle(after, (x, y), (x + w, y + h), (36,255,12), 2)
            cv2.imwrite("static/test/ggg.jpg", mm)

            image = cv2.imread("static/test/ggg.jpg")
            h1=h+10
            w1=w+30
            
            
            cropped = image[y:y+h1, x:x+w1]
            gg="static/test/f"+str(j)+".jpg"
            cv2.imwrite(""+gg, cropped)
        
            cv2.rectangle(diff_box, (x, y), (x + w, y + h), (36,255,12), 2)
            cv2.drawContours(mask, [c], 0, (255,255,255), -1)
            cv2.drawContours(filled_after, [c], 0, (0,255,0), -1)
            j+=1


    #print(j)
    ###################
    textarr=[]
    
    k=1
    while k<j:
        dt=[]
        ############
        fna="f"+str(k)+".jpg"
        print(fna)
        pytesseract.pytesseract.tesseract_cmd = 'C:\\Program Files\\Tesseract-OCR\\tesseract.exe'
        Actual_image = cv2.imread("static/test/"+fna)
        #Sample_img = cv2.resize(Actual_image,(400,350))
        Image_ht,Image_wd,Image_thickness = Actual_image.shape
        Sample_img = cv2.cvtColor(Actual_image,cv2.COLOR_BGR2RGB)
        texts = pytesseract.image_to_data(Sample_img) 
        mytext=""
        prevy=0

        
        
        for cnt,text in enumerate(texts.splitlines()):
            
            if cnt==0:
                continue
            text = text.split()
            if len(text)==12:
                x,y,w,h = int(text[6]),int(text[7]),int(text[8]),int(text[9])
                if(len(mytext)==0):
                    prey=y
                if(prevy-y>=10 or y-prevy>=10):
                    #print(mytext)
                    s=1
                    #mytext=""
                mytext = mytext + text[11]+" "
                prevy=y

        v11=mytext
        print(v11)
        if v11=="":
            dt.append("")
            dt.append(fna)
        else:
            dt.append(v11)
            dt.append(fna)
            
        textarr.append(dt)
        
        k+=1

    #print(textarr)

    
    #####
    



    return render_template('tamper.html',value=value,msg=msg,data=data,data1=data1,act=act,dat1=dat1,dat3=dat3,fstatus=fstatus,textarr=textarr)

@app.route('/tamper2', methods=['GET', 'POST'])
def tamper2():
    
    msg=""
    hashval=""
    filename=""
    fstatus=""
    dat3=[]
    act = request.args.get('act')
    #if 'username' in session:
    #    uname = session['username']
    uname=request.args.get('uu')

    name=""
    message=""
    
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM nt_register where uname=%s",(uname, ))
    value = mycursor.fetchone()

    mycursor.execute("SELECT * FROM nt_tamper where uname=%s",(uname, ))
    data = mycursor.fetchone()
    canno=data[2]

    mycursor.execute("SELECT * FROM nt_certificate_issued where kyc_code=%s",(canno, ))
    data1 = mycursor.fetchone()


    
    ############
    '''if data[6]==1:
        #resize
        img = cv2.imread('static/data/C'+data1[2])
        rez = cv2.resize(img, (100, 100))
        cv2.imwrite("static/test/t1.jpg", rez)

        img = cv2.imread('static/test/C'+data[5])
        rez = cv2.resize(img, (100, 100))
        cv2.imwrite("static/test/t2.jpg", rez)
        
        cutoff=1
        hash0 = imagehash.average_hash(Image.open("static/test/t1.jpg")) 
        hash1 = imagehash.average_hash(Image.open("static/test/t2.jpg"))
        cc1=hash1 - hash0
        print("cc="+str(cc1))
        if cc1<=cutoff:
            fstatus="1"
        else:
            fstatus="2"'''

    ############
    '''txt1=data1[6]
    txt2=data[7]

    dat1=txt1.split(" ")
    dat2=txt2.split(" ")

    l2=len(dat2)
    
    i=0
    for nn in dat1:
        dt=[]
        if i<l2:
            if nn==dat2[i]:
                dt.append(dat2[i])
                dt.append("1")
            else:
                dt.append(dat2[i])
                dt.append("2")
            dat3.append(dt)
        i+=1'''
    ####
    txt1=data1[6]
    txt2=data[7]

    dat1=txt1.split("|")
    dat2=txt2.split("|")

    l2=len(dat2)
    
    i=0
    for nn in dat1:
        dt=[]
        if i<l2:
            if nn==dat2[i]:
                dt.append(dat2[i])
                dt.append("1")
            else:
                dt.append(dat2[i])
                dt.append("2")
            dat3.append(dt)
        i+=1

    ###################
    before = cv2.imread('static/data/'+data1[2])
    after = cv2.imread('static/test/'+data[5])

    # Convert images to grayscale
    before_gray = cv2.cvtColor(before, cv2.COLOR_BGR2GRAY)
    after_gray = cv2.cvtColor(after, cv2.COLOR_BGR2GRAY)

    # Compute SSIM between the two images
    (score, diff) = structural_similarity(before_gray, after_gray, full=True)
    print("Image Similarity: {:.4f}%".format(score * 100))
    per=format(score * 100)

    # The diff image contains the actual image differences between the two images
    # and is represented as a floating point data type in the range [0,1] 
    # so we must convert the array to 8-bit unsigned integers in the range
    # [0,255] before we can use it with OpenCV
    diff = (diff * 255).astype("uint8")
    diff_box = cv2.merge([diff, diff, diff])

    # Threshold the difference image, followed by finding contours to
    # obtain the regions of the two input images that differ
    thresh = cv2.threshold(diff, 0, 255, cv2.THRESH_BINARY_INV | cv2.THRESH_OTSU)[1]
    contours = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    contours = contours[0] if len(contours) == 2 else contours[1]

    mask = np.zeros(before.shape, dtype='uint8')
    filled_after = after.copy()
    j=1
    for c in contours:
        area = cv2.contourArea(c)
        if area > 40:
            x,y,w,h = cv2.boundingRect(c)
            cv2.rectangle(before, (x, y), (x + w, y + h), (36,255,12), 2)
            mm=cv2.rectangle(after, (x, y), (x + w, y + h), (36,255,12), 2)
            cv2.imwrite("static/test/ggg.jpg", mm)

            image = cv2.imread("static/test/ggg.jpg")
            h1=h+10
            w1=w+30
            
            
            cropped = image[y:y+h1, x:x+w1]
            gg="static/test/f"+str(j)+".jpg"
            cv2.imwrite(""+gg, cropped)
        
            cv2.rectangle(diff_box, (x, y), (x + w, y + h), (36,255,12), 2)
            cv2.drawContours(mask, [c], 0, (255,255,255), -1)
            cv2.drawContours(filled_after, [c], 0, (0,255,0), -1)
            j+=1


    #print(j)
    ###################
    textarr=[]
    
    k=1
    while k<j:
        dt=[]
        ############
        fna="f"+str(k)+".jpg"
        print(fna)
        pytesseract.pytesseract.tesseract_cmd = 'C:\\Program Files\\Tesseract-OCR\\tesseract.exe'
        Actual_image = cv2.imread("static/test/"+fna)
        #Sample_img = cv2.resize(Actual_image,(400,350))
        Image_ht,Image_wd,Image_thickness = Actual_image.shape
        Sample_img = cv2.cvtColor(Actual_image,cv2.COLOR_BGR2RGB)
        texts = pytesseract.image_to_data(Sample_img) 
        mytext=""
        prevy=0

        
        
        for cnt,text in enumerate(texts.splitlines()):
            
            if cnt==0:
                continue
            text = text.split()
            if len(text)==12:
                x,y,w,h = int(text[6]),int(text[7]),int(text[8]),int(text[9])
                if(len(mytext)==0):
                    prey=y
                if(prevy-y>=10 or y-prevy>=10):
                    #print(mytext)
                    s=1
                    #mytext=""
                mytext = mytext + text[11]+" "
                prevy=y

        v11=mytext
        print(v11)
        if v11=="":
            dt.append("")
            dt.append(fna)
        else:
            dt.append(v11)
            dt.append(fna)
            
        textarr.append(dt)
        
        k+=1

    #print(textarr)

    
    #####

        


    



    return render_template('tamper2.html',value=value,msg=msg,data=data,data1=data1,act=act,dat1=dat1,dat3=dat3,fstatus=fstatus,textarr=textarr)


@app.route('/user_certificate', methods=['GET', 'POST'])
def user_certificate():
    uname=""
    msg=""
    act = ""
    cid = request.args.get('cid')
    if 'username' in session:
        uname = session['username']
    name=""
    print(uname)
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM nt_register where uname=%s",(uname, ))
    value = mycursor.fetchone()
    prk=value[7]
    pbkey=value[8]
    name=value[1]

    mycursor.execute("SELECT * FROM nt_certificate where uname=%s && id=%s",(uname,cid))
    data = mycursor.fetchone()
    k=data[12]
    efile=""+data[3]
    dfile=data[3]
    if request.method=='POST':
        
        key=request.form['key']
        if k==key:
            act="yes"
            #Decrypt
            password_provided = prk # This is input in the form of a string
            password = password_provided.encode() # Convert to type bytes
            salt = b'salt_' # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            input_file = 'static/upload/'+efile
            output_file = 'static/decrypted/'+dfile
            with open(input_file, 'rb') as f:
                data = f.read()

            fernet = Fernet(key)
            encrypted = fernet.decrypt(data)

            with open(output_file, 'wb') as f:
                f.write(encrypted)
        else:
            act="no"
        

    return render_template('user_certificate.html',act=act,value=value,msg=msg,data=data,fname=dfile)


@app.route('/certificate', methods=['GET', 'POST'])
def certificate():
    uname=""
    msg=""
    act = ""
    cid = request.args.get('cid')

    
    mycursor = mydb.cursor()

    mycursor.execute("SELECT * FROM nt_certificate where id=%s",(cid,))
    data = mycursor.fetchone()
    uname=data[1]
    cno=data[7]
    c_status=data[13]

    
    
    mycursor.execute("SELECT * FROM nt_register where uname=%s",(uname, ))
    value = mycursor.fetchone()
    prk=value[7]
    pbkey=value[8]
    name=value[1]

    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
    
    k=data[12]
    efile="E"+data[3]
    dfile=data[3]
    if request.method=='POST':
        
        key=request.form['key']
        if c_status==1:
            if pbkey==key:
                act="yes"

                ##BC##
                sdata="ID:"+cid+",User:"+name+", UCIC Code:"+cno+", RegDate:"+rdate
                result = hashlib.md5(sdata.encode())
                key=result.hexdigest()

                mycursor1 = mydb.cursor()
                mycursor1.execute("SELECT max(id)+1 FROM nt_blockchain")
                maxid1 = mycursor1.fetchone()[0]
                if maxid1 is None:
                    maxid1=1
                    pkey="00000000000000000000000000000000"
                else:
                    mid=maxid1-1
                    mycursor1.execute('SELECT * FROM nt_blockchain where id=%s',(mid, ))
                    pp = mycursor1.fetchone()
                    pkey=pp[3]
                sql2 = "INSERT INTO nt_blockchain(id,block_id,pre_hash,hash_value,sdata) VALUES (%s, %s, %s, %s, %s)"
                val2 = (maxid1,cid,pkey,key,sdata)
                mycursor1.execute(sql2, val2)
                mydb.commit()   
                ####
                
                #Decrypt
                password_provided = prk # This is input in the form of a string
                password = password_provided.encode() # Convert to type bytes
                salt = b'salt_' # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend()
                )
                key = base64.urlsafe_b64encode(kdf.derive(password))
                input_file = 'static/upload/'+efile
                output_file = 'static/decrypted/'+dfile
                with open(input_file, 'rb') as f:
                    data = f.read()

                fernet = Fernet(key)
                encrypted = fernet.decrypt(data)

                with open(output_file, 'wb') as f:
                    f.write(encrypted)
            else:
                act="no"
                ##BC##
                sdata="ID:"+cid+",User:"+name+", UCIC Code:"+cno+", RegDate:"+rdate+", Access by unauthorized"
                result = hashlib.md5(sdata.encode())
                key=result.hexdigest()

                mycursor1 = mydb.cursor()
                mycursor1.execute("SELECT max(id)+1 FROM nt_blockchain")
                maxid1 = mycursor1.fetchone()[0]
                if maxid1 is None:
                    maxid1=1
                    pkey="00000000000000000000000000000000"
                else:
                    mid=maxid1-1
                    mycursor1.execute('SELECT * FROM nt_blockchain where id=%s',(mid, ))
                    pp = mycursor1.fetchone()
                    pkey=pp[3]
                sql2 = "INSERT INTO nt_blockchain(id,block_id,pre_hash,hash_value,sdata) VALUES (%s, %s, %s, %s, %s)"
                val2 = (maxid1,cid,pkey,key,sdata)
                mycursor1.execute(sql2, val2)
                mydb.commit()   
                ####
        else:
            act="denied"
        

    return render_template('certificate.html',act=act,value=value,msg=msg,data=data,fname=dfile)


@app.route('/certificate1', methods=['GET', 'POST'])
def certificate1():
    uname=""
    msg=""
    act = ""
    cid = request.args.get('cid')

    
    mycursor = mydb.cursor()

    mycursor.execute("SELECT * FROM nt_certificate where id=%s",(cid,))
    data = mycursor.fetchone()
    uname=data[1]
    cno=data[7]
    c_status=data[13]
    ckey=data[12]
    
    mycursor.execute("SELECT * FROM nt_register where uname=%s",(uname, ))
    value = mycursor.fetchone()
    prk=value[7]
    pbkey=value[8]
    name=value[1]

    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
    
    k=data[12]
    efile=""+data[3]
    dfile=data[3]
    if request.method=='POST':

        mycursor.execute("update nt_certificate set c_status=0 where id=%s",(cid,))
        mydb.commit()
        
        key=request.form['key']
        if c_status==1:
            if data[12]==key:
                act="yes"


                krn=randint(1000,9999)
                kkk1=str(krn)
                result = hashlib.md5(kkk1.encode())
                kkk2=result.hexdigest()
                kkk3=kkk2[0:8]

                mycursor.execute("update nt_certificate set ckey=%s where id=%s",(kkk3,cid))
                mydb.commit()
                
                ##BC##
                '''sdata="ID:"+cid+",User:"+name+", KYC Code:"+cno+", RegDate:"+rdate+", Access by "+uname
                result = hashlib.md5(sdata.encode())
                key=result.hexdigest()

                mycursor1 = mydb.cursor()
                mycursor1.execute("SELECT max(id)+1 FROM nt_blockchain")
                maxid1 = mycursor1.fetchone()[0]
                if maxid1 is None:
                    maxid1=1
                    pkey="00000000000000000000000000000000"
                else:
                    mid=maxid1-1
                    mycursor1.execute('SELECT * FROM nt_blockchain where id=%s',(mid, ))
                    pp = mycursor1.fetchone()
                    pkey=pp[3]
                sql2 = "INSERT INTO nt_blockchain(id,block_id,pre_hash,hash_value,sdata) VALUES (%s, %s, %s, %s, %s)"
                val2 = (maxid1,cid,pkey,key,sdata)
                mycursor1.execute(sql2, val2)
                mydb.commit()  ''' 
                ####

                
                #Decrypt
                password_provided = prk # This is input in the form of a string
                password = password_provided.encode() # Convert to type bytes
                salt = b'salt_' # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend()
                )
                key = base64.urlsafe_b64encode(kdf.derive(password))
                input_file = 'static/upload/'+efile
                output_file = 'static/decrypted/'+dfile
                with open(input_file, 'rb') as f:
                    data = f.read()

                fernet = Fernet(key)
                encrypted = fernet.decrypt(data)

                with open(output_file, 'wb') as f:
                    f.write(encrypted)
            else:
                act="no"

        else:
            act="denied"
        

    return render_template('certificate1.html',act=act,value=value,msg=msg,data=data,fname=dfile,ckey=ckey)



@app.route('/user_status', methods=['GET', 'POST'])
def user_status():
    uname=""
    msg=""
    act = request.args.get('act')
    if 'username' in session:
        uname = session['username']
    name=""
    print(uname)
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM nt_register where uname=%s",(uname, ))
    value = mycursor.fetchone()
    prk=value[7]
    pbkey=value[8]
    name=value[1]

    mycursor.execute("SELECT * FROM nt_certificate where uname=%s",(uname, ))
    data = mycursor.fetchall()

    return render_template('user_status.html',value=value,msg=msg,data=data)



@app.route('/user_verify', methods=['GET', 'POST'])
def user_verify():
    fn1=""
    fn=""
    msg=""
    uname=""
    did=""
    if 'username' in session:
        uname = session['username']
    data3=[]
    act=""
    mycursor = mydb.cursor()
    if request.method=='POST':
        
        cno=request.form['cno']
        #key=request.form['key']

        mycursor.execute("SELECT count(*) FROM nt_certificate where canno=%s",(cno,))
        cnt = mycursor.fetchone()[0]
        if cnt>0:
            mycursor.execute("SELECT * FROM nt_certificate where canno=%s",(cno,))
            data = mycursor.fetchone()
            usr=data[1]
            did=data[0]
            mycursor.execute("SELECT * FROM nt_register where uname=%s",(usr,))
            dd = mycursor.fetchone()
            pbkey=dd[8]

            #if pbkey==key:
            fn=data[3]
            fnn="ER"+fn
            fn1="R"+fn

            mycursor.execute("SELECT * FROM nt_blockchain where block_id=%s",(did,))
            data3 = mycursor.fetchall()
            act="yes"
            #else:
            #    msg="Wrong key!!"
            msg="yes"
        else:
            msg="wrong"
            
    
    return render_template('user_verify.html',data3=data3,msg=msg,fname=fn,act=act,cid=did)

@app.route('/user_verify1', methods=['GET', 'POST'])
def user_verify1():
    fn1=""
    fn=""
    msg=""
    uname=""
    data1=[]
    cid=request.args.get("cid")
    if 'username' in session:
        uname = session['username']
    data3=[]
    act=request.args.get("act")
    mycursor = mydb.cursor()

    mycursor.execute("SELECT * FROM nt_certificate where id=%s",(cid,))
    data = mycursor.fetchone()
    fn=data[3]
    usr=data[1]
    hkey=data[12]
    canno=data[7]
    
    mycursor.execute("SELECT * FROM nt_register where uname=%s",(usr,))
    dd = mycursor.fetchone()
    pbkey=dd[8]

    ff=open("static/certificatechain.json","r")
    fj=ff.read()
    ff.close()


    ################
    if act=="1":
        #dataframe = pd.read_json("static/certificatechain.json", orient='values')
        

        ff=open("static/js/d1.txt","r")
        ds=ff.read()
        ff.close()

        drow=ds.split("#|")
        
        i=0
        for dr in drow:
            
            dr1=dr.split("##")
            dt=[]
            if canno in dr1[2]:
                
                dt.append(dr1[0])
                dt.append(dr1[1])
                dt.append(dr1[2])
                dt.append(dr1[3])
                #dt.append(dr1[4])
                data1.append(dt)
    if act=="11":
        s1="1"
        ff=open("static/js/d1.txt","r")
        ds=ff.read()
        ff.close()

        drow=ds.split("#|")
        
        i=0
        for dr in drow:
            
            dr1=dr.split("##")
            dt=[]
            if canno in dr1[2]:
                
                dt.append(dr1[0])
                dt.append(dr1[1])
                dt.append(dr1[2])
                dt.append(dr1[3])
                #dt.append(dr1[4])
                data1.append(dt)

        
                
    '''if request.method=='POST':

        key=request.form['key']

        mycursor.execute("SELECT count(*) FROM nt_certificate where id=%s",(cid,))
        cnt = mycursor.fetchone()[0]
        if hkey==key:

            mycursor.execute("SELECT * FROM nt_blockchain where block_id=%s",(cid,))
            data3 = mycursor.fetchall()
            act="yes"
            #else:
            #    msg="Wrong key!!"
        else:
            msg="Wrong Key!!"'''
            
    
    return render_template('user_verify1.html',data3=data3,msg=msg,fname=fn,act=act,cid=cid,data1=data1)

@app.route('/share', methods=['GET', 'POST'])
def share():
    
    act=""
    uname=""
    email=""
    message=""
    fid = request.args.get('fid')
    if 'username' in session:
        uname = session['username']
    data3=[]

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM nt_register where uname=%s",(uname, ))
    value = mycursor.fetchone()
    prk=value[7]
    pbkey=value[8]
    name=value[1]

    
    mycursor.execute("SELECT * FROM nt_certificate where id=%s",(fid,))
    data = mycursor.fetchone()
    fname=data[3]
    cn=data[7]
    key=data[12]
    link="http://localhost:5000/certificate?cid="+fid

    if request.method=='POST':

        mycursor.execute("update nt_certificate set status=1,c_status=1 where id=%s",(fid,))
        mydb.commit()
        email=request.form['email']
        message="Certificate send by "+uname+", UCIC Code: "+cn+", Key:"+pbkey+", Link:"+link
        #url="http://iotcloud.co.in/testmail/sendmail.php?email="+email+"&message="+message
        #webbrowser.open_new(url)
        act="1"
        
    return render_template('share.html',act=act,link=link,fid=fid,message=message,email=email)


@app.route('/add_proof', methods=['GET', 'POST'])
def add_proof():
    uname=""
    if 'username' in session:
        uname = session['username']
    name=""
    cid = request.args.get('cid')
    act = request.args.get('act')
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM nt_register where uname=%s",(uname, ))
    value = mycursor.fetchone()
    name=value[1]

    mycursor.execute("SELECT * FROM nt_certificate where id=%s",(cid,))
    data = mycursor.fetchone()

    prk=value[7]
    pbkey=value[8]

    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
    
    if request.method=='POST':
        
        detail=request.form['detail']

        mycursor.execute("SELECT max(id)+1 FROM nt_proof")
        maxid = mycursor.fetchone()[0]
        if maxid is None:
            maxid=1
            
        

        
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        
        file_type = file.content_type
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file:
            fname = "P"+str(maxid)+file.filename
            filename = secure_filename(fname)
            
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        

        ##encryption
        password_provided = pbkey # This is input in the form of a string
        password = password_provided.encode() # Convert to type bytes
        salt = b'salt_' # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))

        input_file = 'static/upload/'+fname
        output_file1 = 'static/upload/E'+fname
        with open(input_file, 'rb') as f:
            data = f.read()

        fernet = Fernet(key)
        encrypted = fernet.encrypt(data)

        with open(output_file1, 'wb') as f:
            f.write(encrypted)
            
        
        
        ##store
        sql = "INSERT INTO nt_proof(id,uname,cid,filename,detail,rdate) VALUES (%s, %s, %s, %s, %s, %s)"
        val = (maxid,uname,cid,filename,detail,rdate)
        mycursor.execute(sql,val)
        mydb.commit()
        
        msg="Upload success"
        return redirect(url_for('add_proof'))
            
    mycursor.execute("SELECT * FROM nt_proof where cid=%s",(cid,))
    data2 = mycursor.fetchall()

    if act=="apply":
        print("")
        mycursor.execute("update nt_certificate set status=1 where id=%s", (cid,))
        mydb.commit()
        
        

    
    return render_template('add_proof.html',value=value,cid=cid,data=data,data2=data2)



@app.route('/home_cca', methods=['GET', 'POST'])
def home_cca():
    uname=""
    sid=""
    if 'username' in session:
        uname = session['username']
    name=""
    
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM nt_require where verifier=%s && status=1",(uname,))
    data = mycursor.fetchall()
    
    
        
    return render_template('home_cca.html',data=data)


@app.route('/add_require', methods=['GET', 'POST'])
def add_require():
    uname=""
    if 'username' in session:
        uname = session['username']
    name=""
    cid = request.args.get('cid')
    act = request.args.get('act')
    mycursor = mydb.cursor()
    #mycursor.execute("SELECT * FROM nt_register where uname=%s",(uname, ))
    #value = mycursor.fetchone()
    #name=value[1]

    mycursor.execute("SELECT * FROM nt_certificate where id=%s",(cid,))
    data2 = mycursor.fetchone()

    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
    
    if request.method=='POST':
        
        detail=request.form['detail']

        mycursor.execute("SELECT max(id)+1 FROM nt_require")
        maxid = mycursor.fetchone()[0]
        if maxid is None:
            maxid=1
            
        
        
        ##store
        sql = "INSERT INTO nt_require(id,uname,cid,detail,rdate) VALUES (%s, %s, %s, %s, %s)"
        val = (maxid,uname,cid,detail,rdate)
        mycursor.execute(sql,val)
        mydb.commit()
        
        msg="Upload success"
        return redirect(url_for('add_require',cid=cid,act=act))
            
    mycursor.execute("SELECT * FROM nt_proof where cid=%s",(cid,))
    data = mycursor.fetchall()
    
    return render_template('add_require.html',act=act,cid=cid,data=data,data2=data2)


@app.route('/send_req', methods=['GET', 'POST'])
def send_req():
    uname=""
    if 'username' in session:
        uname = session['username']
    name=""
    act=request.args.get('act')
    mycursor = mydb.cursor()
    

    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
    
    if request.method=='POST':
        
        userid=request.form['userid']
      

        mycursor.execute("SELECT count(*) FROM nt_register where uname=%s",(userid,))
        ds = mycursor.fetchone()[0]
        if ds>0:
            return redirect(url_for('send_req1',userid=userid))
        else:
            act="1"
    
    return render_template('send_req.html',act=act)

@app.route('/send_req1', methods=['GET', 'POST'])
def send_req1():
    uname=""
    if 'username' in session:
        uname = session['username']
    name=""
    act=request.args.get('act')
    userid=request.args.get('userid')
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM nt_certificate where uname=%s",(userid,))
    udata = mycursor.fetchall()

    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
    
    if request.method=='POST':
        
        
        cid=request.form['cid']

        mycursor.execute("SELECT * FROM nt_certificate where id=%s",(cid,))
        cc = mycursor.fetchone()
        detail=cc[4]
        cno=cc[7]

        mycursor.execute("SELECT * FROM nt_register where uname=%s",(userid,))
        dd = mycursor.fetchone()
        ckey=dd[8]

        mycursor.execute("SELECT max(id)+1 FROM nt_require")
        maxid = mycursor.fetchone()[0]
        if maxid is None:
            maxid=1
            
        
        
        ##store
        sql = "INSERT INTO nt_require(id,uname,cid,detail,rdate,verifier,cno,ckey) VALUES (%s, %s, %s, %s, %s, %s,%s,%s)"
        val = (maxid,userid,cid,detail,rdate,uname,cno,ckey)
        mycursor.execute(sql,val)
        mydb.commit()
        act="1"
        msg="success"
        return redirect(url_for('send_req1',act=act))
        
    
    return render_template('send_req1.html',act=act,udata=udata,userid=userid)

@app.route('/sharereq', methods=['GET', 'POST'])
def sharereq():
    uname=""
    act=request.args.get('act')
    rid=request.args.get('rid')
    cid=request.args.get('cid')
    sid=""
    if 'username' in session:
        uname = session['username']
    name=""
    
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM nt_certificate where uname=%s",(uname,))
    cdata = mycursor.fetchall()
    
    mycursor.execute("SELECT * FROM nt_register where uname=%s",(uname, ))
    value = mycursor.fetchone()
    name=value[1]
    prk=value[7]
    pbkey=value[8]
    mycursor.execute("update nt_certificate set c_status=1 where id=%s",(cid,))
    mydb.commit()
    mycursor.execute("update nt_require set status=1 where id=%s",(rid,))
    mydb.commit()
    act='1'
    '''if request.method=='POST':
        
        cid=request.form['cid']
        mycursor.execute("SELECT * FROM nt_certificate where id=%s",(cid,))
        cdd = mycursor.fetchone()

        cno=cdd[7]
        ckey=cdd[12]

        mycursor.execute("update nt_certificate set c_status=1 where id=%s",(cid,))
        mydb.commit()

        mycursor.execute("update nt_require set cid=%s,cno=%s,ckey=%s,status=1 where id=%s",(cid,cno,pbkey,rid))
        mydb.commit()
        return redirect(url_for('sharereq',act='1'))'''
        
    
        
    return render_template('sharereq.html',cdata=cdata,act=act)

@app.route('/view_req', methods=['GET', 'POST'])
def view_req():
    uname=""
    sid=""
    if 'username' in session:
        uname = session['username']
    name=""
    
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM nt_require where uname=%s order by id desc",(uname,))
    data = mycursor.fetchall()
    
    
        
    return render_template('view_req.html',data=data)


@app.route('/verify_cca', methods=['GET', 'POST'])
def verify_cca():
    uname=""
    if 'username' in session:
        uname = session['username']
    name=""
    cid = request.args.get('cid')
    act = request.args.get('act')
    mycursor = mydb.cursor()
    
    mycursor.execute("SELECT * FROM nt_certificate where id=%s && status=0",(cid,))
    data = mycursor.fetchone()
    fn=data[3]
    fnn="R"+fn
    usr=data[1]
    mycursor.execute("SELECT * FROM nt_register where uname=%s",(usr, ))
    value = mycursor.fetchone()
    pbkey=value[8]
    
    mycursor.execute("SELECT * FROM nt_proof where cid=%s",(cid,))
    data2 = mycursor.fetchall()

    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
    
    if act=="transfer":
        mycursor.execute("update nt_certificate set status=2,transfer_cca=%s where id=%s", (rdate,cid))
        mydb.commit()

        ################
        
        filepath = "static/upload/"+fn
        '''img = Image.open(filepath)
          
        # get width and height
        width = img.width
        height = img.height
        w=width-140
        h=height-120
        w2=width-200
        h2=height-80

        # Opening the primary image (used in background)
        img1 = Image.open(filepath)
          
        # Opening the secondary image (overlay image)
        img2 = Image.open("static/images/seal2.png")
        img3 = Image.open("static/images/sign3.png")
          
        # Pasting img2 image on top of img1 
        # starting at coordinates (0, 0)
        img1.paste(img2, (w,h), mask = img2)
        img1.paste(img3, (w2,h2), mask = img3)
        img1.save("static/upload/"+fnn)'''
        ###
        ##encryption
        password_provided = pbkey # This is input in the form of a string
        password = password_provided.encode() # Convert to type bytes
        salt = b'salt_' # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))

        input_file = 'static/upload/'+fnn
        output_file = 'static/upload/E'+fnn
        with open(input_file, 'rb') as f:
            data11 = f.read()

        fernet = Fernet(key)
        encrypted = fernet.encrypt(data11)

        with open(output_file, 'wb') as f:
            f.write(encrypted)
        ###############################
        ##BC##
        sdata="ID:"+cid+", Verifier:"+uname+", Verified, RegDate:"+rdate
        result = hashlib.md5(sdata.encode())
        key=result.hexdigest()

        mycursor1 = mydb.cursor()
        mycursor1.execute("SELECT max(id)+1 FROM nt_blockchain")
        maxid1 = mycursor1.fetchone()[0]
        if maxid1 is None:
            maxid1=1
            pkey="00000000000000000000000000000000"
        else:
            mid=maxid1-1
            mycursor1.execute('SELECT * FROM nt_blockchain where id=%s',(mid, ))
            pp = mycursor1.fetchone()
            pkey=pp[3]
        sql2 = "INSERT INTO nt_blockchain(id,block_id,pre_hash,hash_value,sdata) VALUES (%s, %s, %s, %s, %s)"
        val2 = (maxid1,cid,pkey,key,sdata)
        mycursor1.execute(sql2, val2)
        mydb.commit()   
        ####
        return redirect(url_for('transfer_cca'))
    elif act=="reject":
        mycursor.execute("update nt_certificate set status=3,transfer_cca=%s where id=%s", (rdate,cid))
        mydb.commit()
        ##BC##
        sdata="ID:"+cid+", Verifier:"+uname+", Rejected, RegDate:"+rdate
        result = hashlib.md5(sdata.encode())
        key=result.hexdigest()

        mycursor1 = mydb.cursor()
        mycursor1.execute("SELECT max(id)+1 FROM nt_blockchain")
        maxid1 = mycursor1.fetchone()[0]
        if maxid1 is None:
            maxid1=1
            pkey="00000000000000000000000000000000"
        else:
            mid=maxid1-1
            mycursor1.execute('SELECT * FROM nt_blockchain where id=%s',(mid, ))
            pp = mycursor1.fetchone()
            pkey=pp[3]
        sql2 = "INSERT INTO nt_blockchain(id,block_id,pre_hash,hash_value,sdata) VALUES (%s, %s, %s, %s, %s)"
        val2 = (maxid1,cid,pkey,key,sdata)
        mycursor1.execute(sql2, val2)
        mydb.commit()   
        ####
        return redirect(url_for('transfer_cca'))
    
    
    return render_template('verify_cca.html',act=act,cid=cid,data=data,data2=data2)



@app.route('/approve_cca', methods=['GET', 'POST'])
def approve_cca():
    uname=""
    sid=""
    if 'username' in session:
        uname = session['username']
    name=""
    
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM nt_certificate where status=2")
    data = mycursor.fetchall()
    
    
        
    return render_template('approve_cca.html',data=data)

@app.route('/cca_verify', methods=['GET', 'POST'])
def cca_verify():
    uname=""
    sid=""
    if 'username' in session:
        uname = session['username']
    name=""
    
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM nt_certificate where status=1")
    data = mycursor.fetchall()
    
    
        
    return render_template('cca_verify.html',data=data)


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    fn1=""
    msg=""
    data3=[]
    act=""
    mycursor = mydb.cursor()
    if request.method=='POST':
        
        cno=request.form['cno']
        key=request.form['key']

        mycursor.execute("SELECT count(*) FROM nt_certificate where canno=%s",(cno,))
        cnt = mycursor.fetchone()[0]
        if cnt>0:
            mycursor.execute("SELECT * FROM nt_certificate where canno=%s",(cno,))
            data = mycursor.fetchone()
            usr=data[1]
            did=data[0]
            mycursor.execute("SELECT * FROM nt_register where uname=%s",(usr,))
            dd = mycursor.fetchone()
            pbkey=dd[8]

            if pbkey==key:
                fn=data[3]
                fnn="ER"+fn
                fn1="R"+fn

                mycursor.execute("SELECT * FROM nt_blockchain where block_id=%s",(did,))
                data3 = mycursor.fetchall()
                act="yes"
            else:
                msg="Wrong key!!"
        else:
            msg="Wrong UCIC Code!!"
            
    
    return render_template('verify.html',data3=data3,msg=msg,fname=fn1,act=act)

#Capsule Siamese Network for Tamper detection
def CapsSiamese():
    
    self.args = args
    self.number_of_features = number_of_features
    self.number_of_targets = number_of_targets
    self._setup_layers()

def _setup_base_layers(self):
    """
    Creating GCN layers.
    """
    self.base_layers = [GCNConv(self.number_of_features, self.args.gcn_filters)]
    for _ in range(self.args.gcn_layers-1):
        self.base_layers.append(GCNConv(self.args.gcn_filters, self.args.gcn_filters))
    self.base_layers = ListModule(*self.base_layers)

def _setup_primary_capsules(self):
    """
    Creating primary capsules.
    """
    self.first_capsule = PrimaryCapsuleLayer(in_units=self.args.gcn_filters,
                                             in_channels=self.args.gcn_layers,
                                             num_units=self.args.gcn_layers,
                                             capsule_dimensions=self.args.capsule_dimensions)

def _setup_attention(self):
    """
    Creating attention layer.
    """
    self.attention = Attention(self.args.gcn_layers*self.args.capsule_dimensions,
                               self.args.inner_attention_dimension)

def _setup_reconstruction_layers(self):
    """
    Creating histogram reconstruction layers.
    """
    self.reconstruction_layer_1 = torch.nn.Linear(self.number_of_targets*self.args.capsule_dimensions,
                                                  int((self.number_of_features*2)/3))

    self.reconstruction_layer_2 = torch.nn.Linear(int((self.number_of_features*2)/3),
                                                  int((self.number_of_features*3)/2))

    self.reconstruction_layer_3 = torch.nn.Linear(int((self.number_of_features*3)/2),
                                                  self.number_of_features)

def _setup_layers(self):

    self._setup_base_layers()
    self._setup_primary_capsules()
    self._setup_attention()
    self._setup_graph_capsules()
    self._setup_class_capsule()
    self._setup_reconstruction_layers()

def calculate_reconstruction_loss(self, capsule_input, features):

    v_mag = torch.sqrt((capsule_input**2).sum(dim=1))
    _, v_max_index = v_mag.max(dim=0)
    v_max_index = v_max_index.data

    capsule_masked = torch.autograd.Variable(torch.zeros(capsule_input.size()))
    capsule_masked[v_max_index, :] = capsule_input[v_max_index, :]
    capsule_masked = capsule_masked.view(1, -1)

    feature_counts = features.sum(dim=0)
    feature_counts = feature_counts/feature_counts.sum()

    reconstruction_output = torch.nn.functional.relu(self.reconstruction_layer_1(capsule_masked))
    reconstruction_output = torch.nn.functional.relu(self.reconstruction_layer_2(reconstruction_output))
    reconstruction_output = torch.softmax(self.reconstruction_layer_3(reconstruction_output), dim=1)
    reconstruction_output = reconstruction_output.view(1, self.number_of_features)
    reconstruction_loss = torch.sum((features-reconstruction_output)**2)
    return reconstruction_loss

def forward(self, data):

    features = data["features"]
    edges = data["edges"]
    hidden_representations = []

    for layer in self.base_layers:
        features = torch.nn.functional.relu(layer(features, edges))
        hidden_representations.append(features)

    hidden_representations = torch.cat(tuple(hidden_representations))
    hidden_representations = hidden_representations.view(1, self.args.gcn_layers, self.args.gcn_filters, -1)
    first_capsule_output = self.first_capsule(hidden_representations)
    first_capsule_output = first_capsule_output.view(-1, self.args.gcn_layers*self.args.capsule_dimensions)
    rescaled_capsule_output = self.attention(first_capsule_output)
    rescaled_first_capsule_output = rescaled_capsule_output.view(-1, self.args.gcn_layers,
                                                                 self.args.capsule_dimensions)
    graph_capsule_output = self.graph_capsule(rescaled_first_capsule_output)
    reshaped_graph_capsule_output = graph_capsule_output.view(-1, self.args.capsule_dimensions,
                                                              self.args.number_of_capsules)
    class_capsule_output = self.class_capsule(reshaped_graph_capsule_output)
    class_capsule_output = class_capsule_output.view(-1, self.number_of_targets*self.args.capsule_dimensions)
    class_capsule_output = torch.mean(class_capsule_output, dim=0).view(1,
                                                                        self.number_of_targets,
                                                                        self.args.capsule_dimensions)
    recon = class_capsule_output.view(self.number_of_targets, self.args.capsule_dimensions)
    reconstruction_loss = self.calculate_reconstruction_loss(recon, data["features"])
    return class_capsule_output, reconstruction_loss


def CapsTrainer():
    """
    :param args: Arguments object.
    """
    self.args = args
    self.setup_model()

def enumerate_unique_labels_and_targets(self):
    self.train_graph_paths = glob.glob(self.args.train_graph_folder+ending)
    self.test_graph_paths = glob.glob(self.args.test_graph_folder+ending)
    graph_paths = self.train_graph_paths + self.test_graph_paths

    targets = set()
    features = set()
    for path in tqdm(graph_paths):
        data = json.load(open(path))
        targets = targets.union(set([data["target"]]))
        features = features.union(set(data["labels"]))

    self.target_map = create_numeric_mapping(targets)
    self.feature_map = create_numeric_mapping(features)

    self.number_of_features = len(self.feature_map)
    self.number_of_targets = len(self.target_map)

def setup_model(self):
    """
    Enumerating labels and initializing a CapsGNN.
    """
    self.enumerate_unique_labels_and_targets()
    self.model = CapsGNN(self.args, self.number_of_features, self.number_of_targets)

def create_batches(self):
    """
    Batching the graphs for training.
    """
    self.batches = []
    for i in range(0, len(self.train_graph_paths), self.args.batch_size):
        self.batches.append(self.train_graph_paths[i:i+self.args.batch_size])

def create_data_dictionary(self, target, edges, features):

    to_pass_forward = dict()
    to_pass_forward["target"] = target
    to_pass_forward["edges"] = edges
    to_pass_forward["features"] = features
    return to_pass_forward

def create_target(self, data):
    """
    Target createn based on data dicionary.
    :param data: Data dictionary.
    :return : Target vector.
    """
    return  torch.FloatTensor([0.0 if i != data["target"] else 1.0 for i in range(self.number_of_targets)])

def create_edges(self, data):
    """
    Create an edge matrix.
    :param data: Data dictionary.
    :return : Edge matrix.
    """
    edges = [[edge[0], edge[1]] for edge in data["edges"]]
    edges = edges + [[edge[1], edge[0]] for edge in data["edges"]]
    return torch.t(torch.LongTensor(edges))

def create_features(self, data):
    """
    Create feature matrix.
    :param data: Data dictionary.
    :return features: Matrix of features.
    """
    features = np.zeros((len(data["labels"]), self.number_of_features))
    node_indices = [node for node in range(len(data["labels"]))]
    feature_indices = [self.feature_map[label] for label in data["labels"].values()]
    features[node_indices, feature_indices] = 1.0
    features = torch.FloatTensor(features)
    return features

def create_input_data(self, path):
    """
    Creating tensors and a data dictionary with Torch tensors.
    :param path: path to the data JSON.
    :return to_pass_forward: Data dictionary.
    """
    data = json.load(open(path))
    target = self.create_target(data)
    edges = self.create_edges(data)
    features = self.create_features(data)
    to_pass_forward = self.create_data_dictionary(target, edges, features)
    return to_pass_forward

def fit(self):
    """
    Training a model on the training set.
    """
    print("\nTraining started.\n")
    self.model.train()
    optimizer = torch.optim.Adam(self.model.parameters(),
                                 lr=self.args.learning_rate,
                                 weight_decay=self.args.weight_decay)

    for _ in tqdm(range(self.args.epochs), desc="Epochs: ", leave=True):
        random.shuffle(self.train_graph_paths)
        self.create_batches()
        losses = 0
        self.steps = trange(len(self.batches), desc="Loss")
        for step in self.steps:
            accumulated_losses = 0
            optimizer.zero_grad()
            batch = self.batches[step]
            for path in batch:
                data = self.create_input_data(path)
                prediction, reconstruction_loss = self.model(data)
                loss = margin_loss(prediction,
                                   data["target"],
                                   self.args.lambd)
                loss = loss+self.args.theta*reconstruction_loss
                accumulated_losses = accumulated_losses + loss
            accumulated_losses = accumulated_losses/len(batch)
            accumulated_losses.backward()
            optimizer.step()
            losses = losses + accumulated_losses.item()
            average_loss = losses/(step + 1)
            self.steps.set_description("CapsGNN (Loss=%g)" % round(average_loss, 4))

def score(self):
    """
    Scoring on the test set.
    """
    print("\n\nScoring.\n")
    self.model.eval()
    self.predictions = []
    self.hits = []
    for path in tqdm(self.test_graph_paths):
        data = self.create_input_data(path)
        prediction, _ = self.model(data)
        prediction_mag = torch.sqrt((prediction**2).sum(dim=2))
        _, prediction_max_index = prediction_mag.max(dim=1)
        prediction = prediction_max_index.data.view(-1).item()
        self.predictions.append(prediction)
        self.hits.append(data["target"][prediction] == 1.0)

    print("\nAccuracy: " + str(round(np.mean(self.hits), 4)))

def save_predictions(self):
    """
    Saving the test set predictions.
    """
    identifiers = [path.split("/")[-1].strip(".json") for path in self.test_graph_paths]
    out = pd.DataFrame()
    out["id"] = identifiers
    out["predictions"] = self.predictions
    out.to_csv(self.args.prediction_path, index=None)

#######

@app.route('/issuer_home', methods=['GET', 'POST'])
def issuer_home():
    uname=""
    msg=""
    act = ""
    fst=""
    cid = ""
    if 'username' in session:
        uname = session['username']
    name=""
    print(uname)
    
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM nt_issuer where uname=%s",(uname, ))
    value = mycursor.fetchone()

    fnn=""
    fid="1"
    rectface=""
    gg=""

    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
    yr=now.strftime("%d-%m-%Y")
    
    if request.method=='POST':
        detail=request.form['detail']
        file = request.files['file']

        ###

        fn2=file.filename
        file.save(os.path.join("static/test/", fn2))
        md5hash = hashlib.md5(Image.open("static/test/"+fn2).tobytes())
        hashval2=md5hash.hexdigest()
        mycursor.execute("SELECT count(*) FROM nt_certificate_issued where hash_value=%s",(hashval2,))
        hcnt = mycursor.fetchone()[0]
        ###
        if hcnt==0:
            mycursor.execute("SELECT max(id)+1 FROM nt_certificate_issued")
            maxid = mycursor.fetchone()[0]
            if maxid is None:
                maxid=1
            cid=str(maxid)
            fn=file.filename
            fnn="F"+cid+fn
            shutil.copy("static/test/"+fn2,"static/data/"+fnn)
            #file.save(os.path.join("static/data/", fnn))
            
            
            rn1=randint(100,999)
            rn2=randint(100,999)
            val=cid.zfill(3)
            kcode="CI"+str(rn1)+val+str(rn2)
            
            ###RPN Face Detection
            try:
                ##
                # Detect the faces
                image = cv2.imread("static/data/"+fnn)
                face_cascade = cv2.CascadeClassifier('haarcascade_frontalface_default.xml')
                gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
                faces = face_cascade.detectMultiScale(gray, 1.1, 4)
                
                # Draw the rectangle around each face
                j = 1
                for (x, y, w, h) in faces:
                    mm=cv2.rectangle(image, (x, y), (x+w, y+h), (255, 0, 0), 2)
                    rectface="R"+fnn
                    cv2.imwrite("static/data/"+rectface, mm)
                    image = cv2.imread("static/data/"+rectface)
                    cropped = image[y:y+h, x:x+w]
                    gg="C"+fnn
                    cv2.imwrite("static/data/"+gg, cropped)
                    print("yes")
                    fst="yes"
                    j += 1

            except:
                fst="no"
                print("no")

            pytesseract.pytesseract.tesseract_cmd = 'C:\\Program Files\\Tesseract-OCR\\tesseract.exe'
            ############
            Actual_image = cv2.imread("static/data/"+fnn)
            #Sample_img = cv2.resize(Actual_image,(400,350))
            Image_ht,Image_wd,Image_thickness = Actual_image.shape
            Sample_img = cv2.cvtColor(Actual_image,cv2.COLOR_BGR2RGB)
            texts = pytesseract.image_to_data(Sample_img) 
            mytext=""
            prevy=0

            
            
            for cnt,text in enumerate(texts.splitlines()):
                
                if cnt==0:
                    continue
                text = text.split()
                if len(text)==12:
                    x,y,w,h = int(text[6]),int(text[7]),int(text[8]),int(text[9])
                    if(len(mytext)==0):
                        prey=y
                    if(prevy-y>=10 or y-prevy>=10):
                        #print(mytext)
                        s=1
                        #mytext=""
                    mytext = mytext + text[11]+" "
                    prevy=y

            v11=mytext
            

            md5hash = hashlib.md5(Image.open("static/data/"+fnn).tobytes())
            #print(md5hash.hexdigest())
            hashval=md5hash.hexdigest()
            print(hashval)
           
            ##############
            fst1=0
            if fst=="yes":
                fst1=1
            sql2 = "INSERT INTO nt_certificate_issued(id,kyc_code,filename,description,hash_value,face_status,text_value,name,email,issue_date,uname) VALUES (%s, %s, %s, %s, %s,%s,%s,%s,%s,%s,%s)"
            val2 = (maxid,kcode,fnn,detail,hashval,fst1,v11,'','',rdate,uname)
            mycursor.execute(sql2, val2)
            mydb.commit()   
            msg="success"
        else:
            msg="fail"

        
       

    return render_template('issuer_home.html',value=value,msg=msg,act=act,cid=cid,fnn=fnn)

@app.route('/issuer_view', methods=['GET', 'POST'])
def issuer_view():
    uname=""
    msg=""
    act = ""
    fst=""
    cid = request.args.get("cid")
    fnn = request.args.get("fnn")
    
    if 'username' in session:
        uname = session['username']
    name=""
    print(uname)
    
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM nt_issuer where uname=%s",(uname, ))
    value = mycursor.fetchone()

    mycursor.execute("SELECT * FROM nt_certificate_issued where id=%s",(cid, ))
    data = mycursor.fetchone()
    

    return render_template('issuer_view.html',value=value,msg=msg,act=act,cid=cid,fnn=fnn,data=data)

@app.route('/issuer_send', methods=['GET', 'POST'])
def issuer_send():
    uname=""
    msg=""
    act = ""
    fst=""
    cid = request.args.get("cid")
    fnn = request.args.get("fnn")
    if 'username' in session:
        uname = session['username']
    name=""
    
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM nt_issuer where uname=%s",(uname, ))
    value = mycursor.fetchone()
    if request.method=='POST':
        
        name=request.form['name']
        email=request.form['email']

        mycursor.execute("update nt_certificate_issued set name=%s,email=%s where id=%s",(name,email,cid))
        mydb.commit()

        mycursor.execute("SELECT * FROM nt_certificate_issued where id=%s",(cid, ))
        dat = mycursor.fetchone()

        rdate=dat[9]
        kcode=dat[1]
        fnn=dat[2]
        hashval=dat[4]
        #Unique Certificate Identifier Code
        bcdata="ID: "+cid+",UCIC Code:"+kcode+", Certificate Holder:"+name+",Hash:"+hashval+", Issued Date: "+rdate+""            
        certificatechain(cid,uname,bcdata,'CI')

        ##send mail
        mess="Dear "+name+", Your Certificate has issued, UCIC Code: "+kcode
        with app.app_context():
            msg = Message(subject="Certificate", sender=app.config.get("MAIL_USERNAME"),recipients=[email], body=mess)
            with app.open_resource("static/data/"+fnn) as fp:  
                msg.attach("static/data/"+fnn, "images/png", fp.read())
            mail.send(msg)

        msg="success"
    

    return render_template('issuer_send.html',value=value,msg=msg,act=act,cid=cid,fnn=fnn)


@app.route('/issuer_certificate', methods=['GET', 'POST'])
def issuer_certificate():
    uname=""
    msg=""
    act = ""
    fst=""
    
    if 'username' in session:
        uname = session['username']
    name=""
    
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM nt_issuer where uname=%s",(uname, ))
    value = mycursor.fetchone()

    mycursor.execute("SELECT * FROM nt_certificate_issued where uname=%s",(uname, ))
    data = mycursor.fetchall()

    return render_template('issuer_certificate.html',value=value,msg=msg,act=act,data=data)


@app.route('/view_block', methods=['GET', 'POST'])
def view_block():
    msg=""
    sid = request.args.get('sid')
    
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM sb_blockchain where block_id=%s",(sid, ))
    data = mycursor.fetchall()
       
    
    return render_template('view_block.html', data=data)





@app.route('/down', methods=['GET', 'POST'])
def down():
    fname = request.args.get('fname')
    path="static/decrypted/"+fname
    return send_file(path, as_attachment=True)



@app.route('/logout')
def logout():
    # remove the username from the session if it is there
    #session.pop('username', None)
    return redirect(url_for('index'))


if __name__ == "__main__":
    app.secret_key = os.urandom(12)
    app.run(debug=True,host='0.0.0.0', port=5000)
