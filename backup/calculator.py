num1=int(input("enter the first number: "))
num2=int(input("enter the second number: "))

# print("enter your choices like +,-,/ or *")

choice=input("enter your choices like +,-,/ or *")

if(choice=="+"):
    print("sum = ",num1+num2)
elif(choice=="-"):
    print("difference = ",num1-num2)
elif(choice=="*"):
    print("multiplication =",num1*num2)
elif(choice=="/"):
    if(num2!=0):
        print("error cannot divide")
    else:
        print("division = ",num1/num2)
else:
    print("invalid choice try again")        

