import time
import threading
import logging
import RPi.GPIO as GPIO
GPIO.setmode(GPIO.BOARD)
GPIO.setwarnings(False)

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "2.020"


class LDRAlarm(threading.Thread):
    """
    Check LDR (Light Diode Resistor) if case has been open
    """
    def __init__(self, q, conf):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.LDR = 18
        self.q = q
        self.magic = conf['MAGIC']

    def chk(self, pin):
        cnt = 0
        GPIO.setup(pin, GPIO.OUT)
        GPIO.output(pin, GPIO.LOW)
        time.sleep(0.1)
        GPIO.setup(pin, GPIO.IN)
        while (GPIO.input(pin) == GPIO.LOW):
            cnt += 1
        return cnt

    def run(self):
        while not self.stoprequest.isSet():
            if self.chk(self.LDR) < 1000:
                self.q.put(self.magic)
                self.join()
            time.sleep(1)

    def join(self):
        GPIO.cleanup()
        self.stoprequest.set()
