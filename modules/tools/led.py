import RPi.GPIO as GPIO
GPIO.setmode(GPIO.BOARD)
GPIO.setwarnings(False)

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "2.020"

def TurnLED():
    pins = [19, 29]
    for pin in pins:
        GPIO.setup(pin,GPIO.OUT)
        GPIO.output(pin,GPIO.HIGH)
