# Internship at TEEware

## cryptography

<h3>대칭 키 알고리즘</h3>
-    	암호화 복호화 키가 같은 알고리즘  DES(US) | SEED(Kr) | AES(US) | ARIA(Kr)
-    	입출력이 16bit 고정으로 16bit 씩 block으로 나누어 암호화함. 
è 단순 16비트씩 나누는 방법 : ECB             
è 전 블록의 암호문을 평문에 섞어 암호화하는 방법 : CBC  첫블록에 IV가 필요

<h3>비대칭 키 알고리즘</h3>
-    	암호화 복호화 키가 같지 않음. 공개 키는 알아도 개인 키는 private임
-    	입출력 사이즈는 키 사이즈와 동일하다. 키 사이즈 제한은 없지만 주로 2048, 3072, 4096 bit
-    	소인수분해 기반의 RSA  , 타원곡선체계 기반의 ECDSA  
 
<h4>RSA</h4>
 
   <키 생성>
 
1. 	서로 다른 임의의 두 소수 p,q를 선택 ( p,q는 클수록 암호화의 안정성이 높아짐)
2. 	n = p*q 두 수를 곱하여 n 을 생성
3. 	오일러 파이 함수값을 구함 -> (p-1)*(q-1)                                          
.  오일러 파이 함수 : 1 ~n-1 에서 파라미터 N 과 서로소인 정수들의 개수                   
.  파라미터 N 이 소수라면 result = n-1                     
.  파라미터 N 이 소수 p,q 의 곱이라면 result = (p-1) * (q-1)           
4. 	오파값 ( (p-1) * (q-1) )과 서로소인 e 를 고름 <- 공개 키    (  1  <  e  <  n-1  )
주로 0x10001 ( 65537 )
5. 	(e*d)mod오파값 = 1 이 되는 d 를 고름 <- 개인 키 (  1  <  d  < 오파값-1  )
- why modulus ? mod를 통해 결과 값을 알기는 쉬우나 결과 값만 주어졌을 때 원래의 값을 찾기 어렵게 함으로써 역방향으로 찾기 힘들게 함.            
  개인 키 ( n , d ) 공개 키 ( n , e)
 
<암호화>
 
      C = M ^ e ( mod n )  공개 키 사용
 
<복호화>
 
       M = C ^ d( mod n )  개인 키 사용
       
<h4>ECDSA</h4>


## Worklist 

[헷갈렸던 친구들](https://coderhs.tistory.com/category/%ED%95%98%EB%A3%A8%EC%82%B4%EC%9D%B4)

- UI ( Vue.js )
  - Session Login
  - Add partition , object
  - Object attribute map setting
  - Show object detail attribute information and permission
  - Object Generate
    - for each algorithm parameter.
  - Object Export
  - Object Delete
  - Object Modify
  - Object En/Decrypt
    - for each algorithm parameter.
  - Object Sign
     - for each algorithm parameter.
  - Unicode <-> Hex <-> Base64 converter
  - Show Loading processing until backend api over
  
  
- BackEnd ( Gin gonic - golang )
  - Development mocking unit test
     - Post
        - Modify
        - En/Decrypt
        - Sign
     - Get
        - Object List
        - Object Detail
        - Partition list
 
  - Production 
      - Generate Object
      - Modify Object
      - Sign / verify

## Result

<img width="1440" alt="스크린샷 2021-08-10 오후 10 37 35" src="https://user-images.githubusercontent.com/73640793/128878190-515a0efe-f6a1-4d42-9acd-90caf92d52e2.png">
<img width="1440" alt="스크린샷 2021-08-10 오후 10 37 48" src="https://user-images.githubusercontent.com/73640793/128878219-034bc22c-3477-4c8c-a75e-9ac5c5b22738.png">
<img width="1438" alt="스크린샷 2021-08-10 오후 10 39 14" src="https://user-images.githubusercontent.com/73640793/128878234-4dd551e6-660f-4ba8-ac07-8882f6f57513.png">
<img width="1440" alt="스크린샷 2021-08-10 오후 10 39 48" src="https://user-images.githubusercontent.com/73640793/128878242-7725c669-10bb-4521-885d-dc973f66e39e.png">
<img width="1440" alt="스크린샷 2021-08-10 오후 10 40 23" src="https://user-images.githubusercontent.com/73640793/128878248-6b1a856a-ab0b-4f3e-9666-073175b6bf5e.png">
<img width="1440" alt="스크린샷 2021-08-10 오후 10 41 27" src="https://user-images.githubusercontent.com/73640793/128878255-398fba0a-89a6-4f73-a22a-813825497e4c.png">
<img width="1440" alt="스크린샷 2021-08-10 오후 10 44 05" src="https://user-images.githubusercontent.com/73640793/128878269-fe035665-6798-41b4-94fa-136ea55a46d9.png">
<img width="1440" alt="스크린샷 2021-08-10 오후 10 43 40" src="https://user-images.githubusercontent.com/73640793/128878275-612dbd28-5ffa-43fc-a729-9e2a9f22aaa5.png">



