func main() {
	libPath := os.Getenv("LIB")
	p := pkcs11.New(libPath)
	// *ctx = p:wq
	arg :=os.Args[1]
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
	switch arg {
	case "list":
		fmt.Println("CASE LIST")
		for i := 0 ; i < len(slots)-1 ; i ++ {
			//Get slot Id
			fmt.Printf("slots[%d]: 0x%x\n",i,slots[i])
			//open session   sessionhandler = session
			session, err := p.OpenSession(slots[i], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
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
			// find Object
			//pubtemp := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS,pkcs11.CKO_PUBLIC_KEY)}
			//privtemp := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS,pkcs11.CKO_PRIVATE_KEY)}
			//aestemp := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS,pkcs11.CKO_SECRET_KEY)}
			if e := p.FindObjectsInit(session, nil); e != nil {
				fmt.Println("nice")
			}
			//p.FindObjectsInit(session, privtemp)
			//p.FindObjectsInit(session,pubtemp)
			objects,_,_ := p.FindObjects(session,100)
			fmt.Println("len :",len(objects))
			template := []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
				pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, nil),
				pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			}

			for j := 0 ; j < len(objects) ; j++ {
				attr,err := p.GetAttributeValue(session,objects[j] ,template)
				_,_ = attr,err
				for _,a := range attr{
					fmt.Printf(" -- %d %s %d \n", a.Type,keytp(a.Type), len(a.Value))
				}
			}
			// Get attributeValue
		}

	default :
		fmt.Println("default")
	}
}


