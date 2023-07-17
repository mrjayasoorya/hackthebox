
## Knowledge required

- To run the exe file
- to know how to read exe files from binary
- What are the linux tools to read binary


How I started

- changed the permission and ran the exe file
    - chmod +x ./behindthescenes
    - wine ./behindthescenes
- Started to know more about it 
- Explored how to read this binary files got few tools
    - https://opensource.com/article/20/4/linux-binary-analysis
    - https://www.baeldung.com/linux/edit-binary-files

- After opening in hexeditor - I have searched for challenge and found the password
- Copy pasting didn't worked , removed dots after 3 characters . Itz . _0n . Ly_ . UD2 .>  
  HTB{%s}


Commands ran:
chmod +x behindthescenes
./behindthescenes
strings ./behindthescenes
ltrace ./behindthescenes
strace -f ./behindthescenes
hexdump -C ./behindthescenes | head
hexeditor ./behindthescenes

. .. .rb. flag .wb. flag .enc .

