#!/usr/bin/env python
from ina219 import INA219
from ina219 import DeviceRangeError
import time
import logging
import csv
from datetime import datetime

SHUNT_OHMS = 0.1
MAX_EXPECTED_AMPS = 0.2


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


CSV_FILE = 'aes.csv'

def read(ina):
    """Legge e stampa i valori di potenza del sensore INA219."""
    try:
        return ina.power()
    except DeviceRangeError as e:
        # Corrente fuori dal range del dispositivo 
        print(e)
        return None

def write_to_csv(timestamp, power):
    """Scrive i dati di potenza in un file CSV con un timestamp."""
    with open(CSV_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, power])

if __name__ == "__main__":
    # inizializzazione INA219
    ina = INA219(SHUNT_OHMS, busnum=1)
    
    ina.configure(ina.RANGE_16V,ina.GAIN_8_320MV, ina.ADC_9BIT)
    
   
    try:
        with open(CSV_FILE, mode='x', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Timestamp', 'Power (mW)'])
    except FileExistsError:
        
        pass
    
   # try:
        while True:            
         
            start_time = time.perf_counter()
            
        
            power = read(ina)
            
           
            end_time = time.perf_counter()

            
            elapsed_time = end_time - start_time
            
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            if power is not None:
                write_to_csv(timestamp, power)
 #               print(f"Potenza salvata: {power} mW")

