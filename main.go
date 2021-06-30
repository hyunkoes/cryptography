package main

import (
	/*"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	//"encoding/base64"*/
	"fmt"
	"github.com/miekg/pkcs11"
	"encoding/binary"
	"os"
	"log"
	"io/ioutil"
)
func byte2string(lst []byte) (string) {
	myString := string(lst[:])
	return myString
}
func keytp(t byte) (string){
	i := int(t)
	switch i {
		case 0: return "RSA"
		case 1: return "DSA"
		case 2: return "DH"
		case 3: return "ECDSA"
		case 31: return "AES"
		default: return "x"
	}
}
func tp(t byte) (string){
	ui := uint(t)
	switch ui{
		case 0: return "DATA"
		case 1: return "CERT"
		case 2: return "PUBKEY"
		case 3: return "PRIVKEY"
		case 4: return "SECRETKEY"
		case 5: return "HW_FEATURE"
		case 6: return "DOMAIN_PARAM"
		case 7: return "MECHANISM"
		case 8: return "OTPKEY"
		default: return "VENDOR"
	}

}
func main() {
	libPath := os.Getenv("LIB")
	p := pkcs11.New(libPath)
	// *ctx = p:wq
	arg :=os.Args[1:]
	if p == nil {
		log.Fatalf("cannot load %s", libPath)
	}
	if err := p.Initialize(); err != nil {
		log.Fatal(err)
	}


	defer p.Finalize()
	slots, err := p.GetSlotList(true)
	if err != nil {
		log.Fatal(err)
	}
	session, err := p.OpenSession(slots[1], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		panic(err)
	}
	defer p.CloseSession(session)
	//Login
	err = p.Login(session,pkcs11.CKU_USER,"3434")
	if err!=nil{
		panic(err)
	}
	defer p.Logout(session)

	switch arg[0] {
	case "list":
		fmt.Println("CASE LIST")
		//Get slot Id
		fmt.Printf("slots[%d]: 0x%x\n",1,slots[1])
		//open session   sessionhandler = session
		// find Object
		if e := p.FindObjectsInit(session, nil); e != nil {
			fmt.Println("nice")
		}
		objects,_,_ := p.FindObjects(session,100)
		template := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL,nil),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE,nil),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS,nil),
		}
		for j := 0 ; j < len(objects) ; j++ {
			attr,err := p.GetAttributeValue(session,objects[j] ,template)
			if err != nil{
				panic(err)
			}
			fmt.Println("\nLabel   : ",byte2string(attr[0].Value))
			fmt.Println("KeyType : ",keytp(attr[1].Value[0]))
			if keytp(attr[1].Value[0]) == "AES" {
				t := []*pkcs11.Attribute{
					pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN,nil),
				}
				at,_ := p.GetAttributeValue(session,objects[j],t)
				fmt.Println("KeySize : " , 8*int(at[0].Value[0]))

			} else if  keytp(attr[1].Value[0]) == "RSA" {
				if  tp(attr[2].Value[0]) == "PUBKEY"{
					t := []*pkcs11.Attribute{
						pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS,nil),
					}
					at,_ := p.GetAttributeValue(session,objects[j],t)
					size := binary.LittleEndian.Uint64(at[0].Value)
					fmt.Println("KeySize : " , size)
				} else if tp(attr[2].Value[0]) == "PRIVKEY"{
					t := []*pkcs11.Attribute{
						pkcs11.NewAttribute(pkcs11.CKA_MODULUS,nil),
					}
					at,_ := p.GetAttributeValue(session,objects[j],t)
					fmt.Println("KeySize : " , 8*len(at[0].Value))
				}
			}
			/*else if keytp(attr[1].Value[0]) == "ECDSA" {
				t := []*pkcs11.Attribute{
					pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS,nil),
				}
				at,_ := p.GetAttributeValue(session,objects[j],t)
				fmt.Println("EC VALUE : " , at[0].Value)
				fmt.Println("EC      : ",string(at[0].Value[:6]))
			}*/
			fmt.Println("Type    : ",tp(attr[2].Value[0]))
			// Get attributeValue
		}
		/* -------------------  모든 오브젝트 조회 ----------------------   */

	case "--gen-rsa":
		label :=""
		if (arg[1] == "--label") {
			label = arg[2]
		}
		publicKeyTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		}
		privateKeyTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		}
		pbk, pvk, e := p.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		publicKeyTemplate, privateKeyTemplate)
		_,_,_ = pbk,pvk,e
		template := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL,label),
		}
		if e != nil {
			fmt.Println("failed to gen rsa keypair")
		}
		if err := p.FindObjectsInit(session, template); err != nil {
                        fmt.Println(err)
                }
                objects,_,_ := p.FindObjects(session,100)
                template = []*pkcs11.Attribute{
                        pkcs11.NewAttribute(pkcs11.CKA_LABEL,label),
                        pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE,nil),
                        pkcs11.NewAttribute(pkcs11.CKA_CLASS,nil),
                }
                for j := 0 ; j < len(objects) ; j++ {
                        attr,err := p.GetAttributeValue(session,objects[j] ,template)
                        if err != nil{
                                panic(err)
                        }
                        fmt.Println("\nLabel   : ",byte2string(attr[0].Value))
                        fmt.Println("KeyType : ",keytp(attr[1].Value[0]))
                        if keytp(attr[1].Value[0]) == "AES" {
                                t := []*pkcs11.Attribute{
                                        pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN,nil),
                                }
                                at,_ := p.GetAttributeValue(session,objects[j],t)
                                fmt.Println("KeySize : " , 8*int(at[0].Value[0]))

                        } else if  keytp(attr[1].Value[0]) == "RSA" {
                                if  tp(attr[2].Value[0]) == "PUBKEY"{
                                        t := []*pkcs11.Attribute{
                                                pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS,nil),
                                        }
                                        at,_ := p.GetAttributeValue(session,objects[j],t)
                                        size := binary.LittleEndian.Uint64(at[0].Value)
                                        fmt.Println("KeySize : " , size)
                                } else if tp(attr[2].Value[0]) == "PRIVKEY"{
                                        t := []*pkcs11.Attribute{
                                                pkcs11.NewAttribute(pkcs11.CKA_MODULUS,nil),
                                        }
                                        at,_ := p.GetAttributeValue(session,objects[j],t)
                                        fmt.Println("KeySize : " , 8*len(at[0].Value))
                                }
                        }
                        /*else if keytp(attr[1].Value[0]) == "ECDSA" {
                                t := []*pkcs11.Attribute{
                                        pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS,nil),
                                }
                                at,_ := p.GetAttributeValue(session,objects[j],t)
                                fmt.Println("EC VALUE : " , at[0].Value)
                                fmt.Println("EC      : ",string(at[0].Value[:6]))
                        }*/
                        fmt.Println("Type    : ",tp(attr[2].Value[0]))
                        // Get attributeValue
                }
                /* ------------------- RSA 키 쌍 생성 ----------------------   */

	case "sign-rsa" :
		label := ""
		_ = label
		msg := ""
		if arg[1] != "--label" {
			panic("--label <label name>")
		}else if ( arg[1] == "--label" ) {
			label = arg[2]
		}
		if arg[3] != "--data"{
			panic("--data <message>")
		}else if arg[3] == "--data" {
			msg = arg[4]
		}
                privateKeyTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE,true),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
                        pkcs11.NewAttribute(pkcs11.CKA_CLASS , pkcs11.CKO_PRIVATE_KEY),
                        pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
                }
                if err := p.FindObjectsInit(session, privateKeyTemplate); err != nil {
                        fmt.Println(err)
                }
                objects,_,_ := p.FindObjects(session,1)
		priv := objects[0]
		p.FindObjectsFinal(session)
		dat, err := ioutil.ReadFile(msg)
                if err != nil {panic(err)}
		data := string(dat)
		fmt.Println(data)
		d := []byte(data)

		err = p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA1_RSA_PKCS,nil)}, priv)
		if err != nil {log.Fatal(err)}
		signature,e := p.Sign(session,d)
		if e != nil {
			log.Fatal(e)
		}
		fmt.Println("Sign success!")
		fmt.Println(signature)
		p.SignFinal(session)
		/* ------------------- 지정한 RSA 키로 데이터 서명 ----------------------   */

	case "--gen-aes":
                label :=""
                if (arg[1] == "--label") {
                        label = arg[2]
                }
                secretKeyTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
                        pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
                        pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
                        pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
		}
                key, e := p.GenerateKey(session,
                []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)},
                secretKeyTemplate)
                _,_ = key,e
                template := []*pkcs11.Attribute{
                        pkcs11.NewAttribute(pkcs11.CKA_LABEL,label),
                }
                if e != nil {
                        fmt.Println("failed to gen aes key")
                }
                if err := p.FindObjectsInit(session, template); err != nil {
                        fmt.Println(err)
                }
                objects,_,_ := p.FindObjects(session,100)
                template = []*pkcs11.Attribute{
                        pkcs11.NewAttribute(pkcs11.CKA_LABEL,label),
                        pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE,nil),
                        pkcs11.NewAttribute(pkcs11.CKA_CLASS,nil),
                }
                for j := 0 ; j < len(objects) ; j++ {
                        attr,err := p.GetAttributeValue(session,objects[j] ,template)
                        if err != nil{
                                panic(err)
                        }
                        fmt.Println("\nLabel   : ",byte2string(attr[0].Value))
                        fmt.Println("KeyType : ",keytp(attr[1].Value[0]))
                        //      fmt.Println("KeySize: ",attr[3].Value)
                        if keytp(attr[1].Value[0]) == "AES" {
                                t := []*pkcs11.Attribute{
                                        pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN,nil),
                                }
                                at,_ := p.GetAttributeValue(session,objects[j],t)
                                fmt.Println("KeySize : " , 8*int(at[0].Value[0]))

                        } else if  keytp(attr[1].Value[0]) == "RSA" {
                                if  tp(attr[2].Value[0]) == "PUBKEY"{
                                        t := []*pkcs11.Attribute{
                                                pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS,nil),
                                        }
                                        at,_ := p.GetAttributeValue(session,objects[j],t)
                                        size := binary.LittleEndian.Uint64(at[0].Value)
                                        fmt.Println("KeySize : " , size)
                                } else if tp(attr[2].Value[0]) == "PRIVKEY"{
                                        t := []*pkcs11.Attribute{
                                                pkcs11.NewAttribute(pkcs11.CKA_MODULUS,nil),
                                        }
                                        at,_ := p.GetAttributeValue(session,objects[j],t)
                                        fmt.Println("KeySize : " , 8*len(at[0].Value))
                                }
                        }
                        /*else if keytp(attr[1].Value[0]) == "ECDSA" {
                                t := []*pkcs11.Attribute{
                                        pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS,nil),
                                }
                                at,_ := p.GetAttributeValue(session,objects[j],t)
                                fmt.Println("EC VALUE : " , at[0].Value)
				fmt.Println("EC      : ",string(at[0].Value[:6]))
			}*/
                        fmt.Println("Type    : ",tp(attr[2].Value[0]))
			// Get attributeValue
		}
                /* -------------------  AES 키 생성 ----------------------   */

	case "encrypt-aes" :
		label := ""
		infile := ""
		outfile := ""
		if arg[1] != "--label" {
			panic("--label <label name>")
		}else if ( arg[1] == "--label" ) {
			label = arg[2]
		}
		if arg[3] != "--in"{
			panic("--in <input file>")
		}else if arg[3] == "--in" {
			infile = arg[4]
		}
		if arg[5] != "--out" {
			panic("--out <out file>")
		}else if arg[5] == "--out" {
			outfile = arg[6]
		}

		fmt.Println(label, " " , infile , " " , outfile)

		dat, err := ioutil.ReadFile(infile)
		if err != nil {panic(err)}
		fmt.Print(string(dat))
                /* ------------------- 지정한 AES 키로 암호화  ----------------------   */
        case "decrypt-aes" :
                label := ""
                infile := ""
                outfile := ""
                if arg[1] != "--label" {
                        panic("--label <label name>")
                }else if ( arg[1] == "--label" ) {
                        label = arg[2]
                }
                if arg[3] != "--in"{
                        panic("--in <input file>")
                }else if arg[3] == "--in" {
                        infile = arg[4]
                }
                if arg[5] != "--out" {
                        panic("--out <out file>")
                }else if arg[5] == "--out" {
                        outfile = arg[6]
                }

                fmt.Println(label, " " , infile , " " , outfile)

                dat, err := ioutil.ReadFile(infile)
                if err != nil {panic(err)}
                fmt.Print(string(dat))
                /* ------------------- 지정한 AES 키로 복호화  ----------------------   */

	default :
		fmt.Println("default")

	}
}


