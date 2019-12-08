import bcrypt

def get_hashed_password(plain_text_password):
    return bcrypt.hashpw(plain_text_password, bcrypt.gensalt())
	
def check_password(plain_text_password):
	with open('C:\Test Files\password.pwd') as f:
		first_line = f.readline()
		return bcrypt.checkpw(plain_text_password, first_line)
	
def save_password(plain_text_password):
	f = open("C:\Test Files\testpassword.pwd", "w")
	f.write(bcrypt.hashpw(plain_text_password, bcrypt.gensalt()))
	f.close()