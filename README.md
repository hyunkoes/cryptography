# cryptography


대칭 키 알고리즘
-    	암호화 복호화 키가 같은 알고리즘  DES(US) | SEED(Kr) | AES(US) | ARIA(Kr)
-    	입출력이 16bit 고정으로 16bit 씩 block으로 나누어 암호화함. 
è 단순 16비트씩 나누는 방법 : ECB             
è 전 블록의 암호문을 평문에 섞어 암호화하는 방법 : CBC  첫블록에 IV가 필요

비대칭 키 알고리즘
-    	암호화 복호화 키가 같지 않음. 공개 키는 알아도 개인 키는 private임
-    	입출력 사이즈는 키 사이즈와 동일하다. 키 사이즈 제한은 없지만 주로 2048, 3072, 4096 bit
-    	소인수분해 기반의 RSA  , 타원곡선체계 기반의 ECDSA  
 
¨ 	RSA
 
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

## To do List ( in vue + golang )

- UI
  - Session Login<br><br>
  - Add partition , object
  - Object attribute map setting : done
  - Show object detail attribute information and permission : done
  - Object Generate : doing..
    - for each algorithm parameter.
  - Object Export : done
  - Object Delete : done
  - Object Modify : done
  - Object En/Decrypt : done
    - for each algorithm parameter.
  - Object Sign : done
     - for each algorithm parameter.<br><br>
  - Unicode <-> Hex <-> Base64 converter : done
- BackEnd
  - mock adapter test
