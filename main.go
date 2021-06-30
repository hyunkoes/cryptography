package main

import (
	"encoding/base64"

	"crypto/rand"
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
//                        pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),

func addAttribute(tp []*pkcs11.Attribute,opt string,val string) ([]*pkcs11.Attribute){
	if tp == nil {
		if opt == "keytype"{
        	        if val == "RSA"||val =="rsa"{
        	                tp = []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE,pkcs11.CKK_RSA)}
        	        } else if val == "AES"||val=="aes" {
        	                tp = []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE,pkcs11.CKK_AES)}
        	        } else if val == "EC"||val=="ec" {
        	                tp = []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE,pkcs11.CKK_EC)}
        	        }
        	}
        	if opt == "id"{
        	        tp = append(tp, pkcs11.NewAttribute(pkcs11.CKA_ID, val))
        	}
	}

	if opt == "keytype"{
		if val == "RSA"||val =="rsa"{
			tp = append(tp, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE,pkcs11.CKK_RSA))
		} else if val == "AES"||val=="aes" {
			tp = append(tp, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE,pkcs11.CKK_AES))
		} else if val == "EC"||val=="ec" {
			tp = append(tp, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE,pkcs11.CKK_EC))
		}
	}
	if opt == "id"{
		tp = append(tp, pkcs11.NewAttribute(pkcs11.CKA_ID, val))
	}
	return tp
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
		var findtp []*pkcs11.Attribute
		if arg[1] == "--key-type" {
			findtp = addAttribute(findtp,"keytype",arg[2])
			if len(arg)>3 && arg[3] == "--id" {
				findtp = addAttribute(findtp,"id", arg[4])
			} else {
				log.Fatal("Invalid option")
			}
		} else if arg[1] == "--id"{
			findtp = addAttribute(findtp,"id", arg[2])
			if len(arg)>3 && arg[3] == "--key-type"{
				findtp = addAttribute(findtp,"keytype",arg[4])
			}else{
				log.Fatal("Invalid option")
			}
		} else {
			log.Fatal("Invalid option")
		}
		// find Object
		if e := p.FindObjectsInit(session, findtp); e != nil {
			fmt.Println("nice")
		}
		objects,_,_ := p.FindObjects(session,100)
		template := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL,nil),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE,nil),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS,nil),
		}
		fmt.Println("1 : ", len(template))

		fmt.Println("2 : ", len(template))
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
		fmt.Println(base64.RawStdEncoding.EncodeToString(signature))
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
                secretKeyTemplate := []*pkcs11.Attribute{
                        pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
                        pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
                        pkcs11.NewAttribute(pkcs11.CKA_CLASS , pkcs11.CKO_SECRET_KEY),
                        pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
                }
                if err := p.FindObjectsInit(session, secretKeyTemplate); err != nil {
                        fmt.Println(err)
                }
                objects,_,_ := p.FindObjects(session,1)
                aeskey := objects[0]
                p.FindObjectsFinal(session)
		//fmt.Println(label, " " , infile , " " , outfile)

		dat, err := ioutil.ReadFile(infile)
		if err != nil {panic(err)}
		data := string(dat)
		//fmt.Print(data)
		iv := make([]byte, 16)
		_, err = rand.Read(iv)
		if err!=nil {log.Fatal(err)}
		err = p.EncryptInit(session , []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD,iv)},aeskey)
                if err!=nil {log.Fatal(err)}
		cipher, err := p.Encrypt(session, []byte(data))
		if err != nil {log.Fatal(err)}
		cdWithIV := append(iv,cipher...)
		base64cipher := base64.RawStdEncoding.EncodeToString(cdWithIV)
		fmt.Printf("Encrypted IV+Cipher %s", base64cipher)
		err = ioutil.WriteFile(outfile,cdWithIV,0644)
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

               // fmt.Println(label, " " , infile , " " , outfile)

                dat, err := ioutil.ReadFile(infile)
                if err != nil {panic(err)}
		//fmt.Println(len(dat))
		//fmt.Print(dat)
		secretKeyTemplate := []*pkcs11.Attribute{
                        pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
                        pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
                        pkcs11.NewAttribute(pkcs11.CKA_CLASS , pkcs11.CKO_SECRET_KEY),
                        pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
                }
                if err := p.FindObjectsInit(session, secretKeyTemplate); err != nil {
                        fmt.Println(err)
                }
                objects,_,_ := p.FindObjects(session,1)
                aeskey := objects[0]
		p.FindObjectsFinal(session)

		err = p.DecryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, dat[0:16])}, aeskey)
		if err != nil {
			panic(fmt.Sprintf("EncryptInit() failed %s\n", err))
		}

		pt, err := p.Decrypt(session, dat[16:])
		if err != nil {
			panic(fmt.Sprintf("Encrypt() failed %s\n", err))
		}

		log.Printf("Decrypt %s", string(pt))
		err = ioutil.WriteFile(outfile,pt,0644)
                /* ------------------- 지정한 AES 키로 복호화  ----------------------   */
	case "--gen-ec":
		curve := "gen ec"
		label := ""
                if arg[1] != "--curve" {
                        panic("--curve <curve type>")
                }else {
                        curve = arg[2]
                }
                if arg[3] != "--label"{
                        panic("--label <label name>")
                }else{
                        label = arg[4]
                }
		if ( curve == "secp256r1" ) {fmt.Println(curve, " 타입으로 생성 시작")
		} else {
			panic("only secp256r1 yet")
		}
		publicKeyTemplate := []*pkcs11.Attribute{
			// oid of P256
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, false),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		}
		privateKeyTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, false),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		}
		_, _, err := p.GenerateKeyPair(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN,nil)}, publicKeyTemplate, privateKeyTemplate)
		if err != nil {
			panic(err)
		}
		fmt.Println("Generate EC key , Label : " , label)
	  /*------------------------curve, label 입력받아 EC 키 쌍 생성 ----------------------------------*/
	case "sign-ec":
                label := ""
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
                        pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
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

                err = p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA,nil)}, priv)
                if err != nil {log.Fatal(err)}
                signature,e := p.Sign(session,d)
                if e != nil {
                        log.Fatal(e)
                }
                fmt.Println("Sign success!")
                fmt.Println(base64.RawStdEncoding.EncodeToString(signature))
                p.SignFinal(session)
		/*------------------------ label로 지정한 EC private key 로 서명하기  ----------------------------------*/
	case "getpub-ec": // EC 공개키 추출
	default :
		fmt.Println("default")

	}
}
