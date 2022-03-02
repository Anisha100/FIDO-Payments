from azure.storage.blob import *
from datetime import *

connect_str='DefaultEndpointsProtocol=https;AccountName=paymentkeys;AccountKey=pxicg6JeqWm2FXDF1VXBfeiHM1LWrWDIN9IqvNDeaUw83v58Og8mr2Of5hUlbXoip6VNkqsWO0e366yhyaFHNw==;EndpointSuffix=core.windows.net'
blob_service_client = BlobServiceClient.from_connection_string(connect_str)

cryptocontainer=blob_service_client.get_container_client('cryptofiles')

def uploadCryptoFile(data,fln):
  blob_client = blob_service_client.get_blob_client(container='cryptofiles', blob=fln)
  blob_client.upload_blob(data, overwrite=True)
  
def downloadCryptoFile(fln):
  blob_client = blob_service_client.get_blob_client(container='cryptofiles', blob=fln)
  return blob_client.download_blob().readall()

def createContainers():
  try:
    container_properties = cryptocontainer.get_container_properties()
  except Exception as e:
    cryptocontainer.create_container()
 
    
def resetContainers():
  try:
    cryptocontainer.delete_container()
  except Exception as e:
    pass
 
