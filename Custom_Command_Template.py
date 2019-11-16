import aiy.audio
import aiy.cloudspeech
import aiy.voicehat
from gpiozero import Servo

def main():


	recognizer = aiy.cloudspeech.get_recognizer()
	recognizer.expect_phrase('maximum')
	recognizer.expect_phrase('minimum')
	recognizer.expect_phrase('middle')

	button = aiy.voicehat.get_button()
	aiy.audio.get_recorder().start()
	
	while True:
		print('Press the button and speak')
		button.wait_for_press()
		print('Listening...')
		text = recognizer.recognize()
		if text is None:
			print('Sorry, I did not hear you.')
		else:
			print('You said "', text, '"')
		if 'maximum' in text:
			print('You said maximum')
		elif 'minimum' in text:
			print('You said minimum')
		elif 'middle' in text:
			print('You said middle')

if __name__ == '__main__':
 main()
