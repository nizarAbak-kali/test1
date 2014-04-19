# To change this license header, choose License Headers in Project Properties. # To change this template file, choose Tools | Templates # and open the template in the editor.
import requests
import httplib 
import hashlib 
import urllib
import urllib2
import ctypes
import httplib,re
from urllib2 import Request, urlopen, URLError
import json 
# -*-coding:utf-8 -*


def chiffrement1(pseudo,cle_crypto,off_cle1):
    chiffrement = len(pseudo)
    chiffrement = chiffrement ^ off_cle1
    chiffrement = chiffrement & 0x3f 
    cle = cle_crypto[chiffrement] 
    return cle 
def chiffrement2(pseudo,cle_crypto,offcle2): 
    res = 0x0 
    for c in pseudo :
        res = res + ord(c)

    r = res & 0xff
    r = r ^ offcle2 
    r = r + (res & 0xff00) 
    r = r & 0x3f 
    cle = cle_crypto[r] 
    return cle

def chiffrement3(pseudo ,cle_crypto,offcle3):
    res = 0x1 
    for c in pseudo:
        res = res * ord(c) 
    res = res & 0xff 
    res = res ^ offcle3 
    res = res & 0x3f 
    cle = cle_crypto[res] 
    return cle

def chiffrement4(pseudo ,cle_crypto,off_cle4): 
    max = pseudo[0]
    for c in pseudo :
        if max < c :
            max = c
    cle = ord(max)
    cle = cle ^ off_cle4 
    alea = ctypes.CDLL("/home/crespo/reverse/alea.so")
    cle = alea.aleatoire(cle)
    cle=cle & 0x3f
    cle=cle_crypto[cle]
    return cle
def chiffrement5(pseudo , cle_crypto, off_cle5):
    tmp = 0 
    res = 0 
    for c in pseudo:
        tmp = ord(c)*ord(c) 
        res = res + tmp 
        res = res & 0xff
    cle = res ^ off_cle5 
    cle = cle & 0x3f
    cle=cle_crypto[cle]
    return cle
def chiffrement6(pseudo , cle_crypto , off_cle6):
    r=ord(pseudo[0])
    alea = ctypes.CDLL("/home/crespo/reverse/alea.so")
    while r>0 :
        a=alea.aleatoire2()
        r = r-1
    a = a & 0xff
    cle = a ^ off_cle6
    cle = cle & 0x3f 
    cle=cle_crypto[cle]
    return cle
def chiffrage(pseudo):
    taille_pseudo = len(pseudo)
    f = open('keygenmefastdl', 'rb')
    f.seek(0x000005d9)
    off_cle1=ord(f.read(1))
    f.seek(0x00000610)
    off_cle2 =ord(f.read(1))
    f.seek(0x00000646)
    off_cle3 =ord(f.read(1))
    f.seek(0x00000679)
    off_cle4 =ord(f.read(1))
    f.seek(0x000006c7)
    off_cle5 =ord(f.read(1))
    f.seek(0x000006fe)
    off_cle6 =ord(f.read(1))
    cle_addr= 0x00001042
    f.seek(0x00001042)
    cle_crypto=""
    cle_crypto= f.read(64)
    f.closed
    mdp=""
    mdp1 = chiffrement1(pseudo, cle_crypto, off_cle1) 
    mdp+= mdp1 
    mdp2 = chiffrement2(pseudo, cle_crypto, off_cle2)
    mdp+= mdp2
    mdp3 = chiffrement3(pseudo, cle_crypto, off_cle3)
    mdp+= mdp3
    mdp4 = chiffrement4(pseudo, cle_crypto, off_cle4)
    mdp+= mdp4 
    mdp5 = chiffrement5(pseudo, cle_crypto, off_cle5)
    mdp+= mdp5
    mdp6 = chiffrement6(pseudo, cle_crypto, off_cle6)
    mdp+= mdp6
    return mdp
def keygen(pseudo):
    psswd = chiffrage(pseudo) 
    return psswd


if __name__ == "__main__":
    
    # connexion
    host = "http://95.142.162.76:8089"
    connexion=httplib.HTTPConnection(host)
    connexion.set_debuglevel(1)
    #telechargement
    elf = urllib2.urlopen("http://95.142.162.76:8089/keygenmefast.php","keygenmefast.php")
    output = open('keygenmefastdl','wb')
    output.write(elf.read())
    output.close()
    # suivi
   
    connexion.request("GET","/keygenmefast.php")
    reponse=connexion.getresponse()
    cookie = reponse.getheader("Set-Cookie")
    contenu =reponse.getheader("X-Pseudo-keygenmefast")
    reponse.read()
    
    login= contenu
    print login 
    serial= keygen(login)
    print serial
    resultat=login+serial
    print resultat
    h= hashlib.sha1()
    h.update(resultat)
    sha1=h.hexdigest()
    print sha1
    headers={"cookie" : cookie}
    print connexion.request("GET", "/verifkeygenmefast.php?solution=" + sha1,"",headers)
    response = connexion.getresponse()
    print response.read()
    # fermeture connexion
    connexion.close()
 
    
