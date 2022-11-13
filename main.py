from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
import json
from waitress import serve
import datetime
import requests
import re

app=Flask(__name__)
cors = CORS(app)
from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
app.config["JWT_SECRET_KEY"]="secret-key" #Cambiar por el que se conveniente
jwt = JWTManager(app)

@app.route("/login", methods=["POST"])
def create_token():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-security"]+'/usuarios/validar'
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 200:
        user = response.json()
        expires = datetime.timedelta(seconds=60 * 60*24)
        access_token = create_access_token(identity=user, expires_delta=expires)
        return jsonify({"token": access_token, "user_id": user["_id"]})
    else:
        return jsonify({"msg": "Bad username or password"}), 401

@app.before_request
def before_request_callback():
    endPoint=limpiarURL(request.path)
    excludedRoutes=["/login"]
    if excludedRoutes.__contains__(request.path):
        pass
    elif verify_jwt_in_request():
        usuario = get_jwt_identity()
        if usuario["rol"]is not None:
            tienePersmiso=validarPermiso(endPoint,request.method,usuario["rol"]["_id"])
            if not tienePersmiso:
                return jsonify({"message": "Permission denied"}), 401
        else:
            return jsonify({"message": "Permission denied"}), 401
def limpiarURL(url):
    partes = url.split("/")
    for laParte in partes:
        if re.search('\\d', laParte):
            url = url.replace(laParte, "?")
    return url
def validarPermiso(endPoint,metodo,idRol):
    url=dataConfig["url-backend-security"]+"/permisos-roles/validar-permiso/rol/"+str(idRol)
    tienePermiso=False
    headers = {"Content-Type": "application/json; charset=utf-8"}
    body={
        "url": endPoint,
        "metodo": metodo
    }
    response = requests.get(url,json=body, headers=headers)
    try:
        data=response.json()
        if("_id" in data):
            tienePermiso=True
    except:
        pass
    return tienePermiso

############################ CANDIDATOS #################################
@app.route("/candidatos",methods=['GET'])
def getCandidatos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/candidatos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/candidatos",methods=['POST'])
def crearCandidato():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/candidatos'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/candidatos/<string:id>",methods=['GET'])
def getCandidato(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/candidatos/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/candidatos/<string:id>",methods=['PUT'])
def modificarCandidato(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/candidatos/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/candidatos/<string:id>",methods=['DELETE'])
def eliminarCandidato(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/candidatos/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/candidatos/<string:id>/partido/<string:id_partido>",methods=['PUT'])
def asignarPartidoACandidato(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/candidatos/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

##########################  MESAS  #########################################

@app.route("/mesas",methods=['GET'])
def getMesas():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/mesas'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/mesas/<string:id>",methods=['GET'])
def getMesa(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/mesas/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/mesas",methods=['POST'])
def crearMesa():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    print(headers)
    url = dataConfig["url-backend-results"] + '/mesas'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)
@app.route("/mesas/<string:id>",methods=['PUT'])
def modificarMesa(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/mesas/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/mesas/<string:id>",methods=['DELETE'])
def eliminarMesa(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/mesas/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

#####################  PARTIDO   #############################

@app.route("/partidos",methods=['GET'])
def getPartidos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/partidos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/partidos/<string:id>",methods=['GET'])
def getPartido(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/partidos/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/partidos",methods=['POST'])
def crearPartido():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/partidos'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)
@app.route("/partidos/<string:id>",methods=['PUT'])
def modificarPartido(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/partidos/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/partidos/<string:id>",methods=['DELETE'])
def eliminarPartido(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/partidos/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

##########################  RESULTADOS  ############################

@app.route("/resultados",methods=['GET'])
def getResultados():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/resultados'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/resultados/<string:id>",methods=['GET'])
def getResultado(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/resultados/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/resultados/mesas/<string:id_mesa>/candidatos/<string:id_candidato>",methods=['POST'])
def crearResultado(id_mesa,id_candidato):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/resultados/mesas/'+id_mesa+'/candidatos/'+id_candidato
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)
@app.route("/resultados/<string:id_resultado>/mesas/<string:id_mesa>/candidatos/<string:id_candidato>",methods=['PUT'])
def modificarResultado(id_resultado,id_mesa,id_candidato):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/resultados/'+id_resultado +'/mesas/'+id_mesa+'/candidatos/'+id_candidato
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/resultados/<string:id>",methods=['DELETE'])
def eliminarResultado(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/resultados/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

############################## OTROS RESULTADOS ###################################

@app.route("/resultados/candidato/<string:id_candidato>",methods=['GET'])
def resultadosCandidato(id_candidato):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/resultados/candidato/'+id_candidato
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/resultados/mesa/<string:id_mesa>",methods=['GET'])
def resultadosPorMesa(id_mesa):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/resultados/mesa/'+id_mesa
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/resultados/candidato_ganador",methods=['GET'])
def getVotosMayores():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/resultados/candidato_ganador'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/resultados/consolidadomesas",methods=['GET'])
def getTotalVotosMesas():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/resultados/consolidadomesas'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/resultados/listaVotosCandidatoPartidosyMesas",methods=['GET'])#
def getConsultaVotosCandidatoPartidoyMesas():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/resultados/listaVotosCandidatoPartidosyMesas'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/resultados/listaVotosCandidatoPartidosxMesa/<string:id_mesa>",methods=['GET'])
def getConsultaVotosCandidatoPartidoxMesa(id_mesa):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/resultados/listaVotosCandidatoPartidosxMesa'+ id_mesa
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/resultados/listaVotosPartidosenMesas",methods=['GET'])
def getConsultaPartidosMesas():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/resultados/listaVotosPartidosenMesas'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/resultados/listaVotosPartidosxMesa/<string:id_mesa>",methods=['GET'])
def getConsultaPartidosxMesa(id_mesa):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/resultados/listaVotosPartidosxMesa/'+ id_mesa
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/resultados/composicionNuevoCongreso",methods=['GET'])
def getComposicionCongreso():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-results"] + '/resultados/composicionNuevoCongreso'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

###################################### USUARIOS ###################################
@app.route("/usuarios",methods=['GET'])
def getUsuarios():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/usuarios",methods=['POST'])
def crearUsuario():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/usuarios/<string:id>",methods=['GET'])
def getUsuario(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/usuarios/<string:id>",methods=['PUT'])
def modificarUsuario(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/usuarios/<string:id>",methods=['DELETE'])
def eliminarUsuario(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/usuarios/<string:id>/rol/<string:id_rol>",methods=['PUT'])
def asignarRolAUsuario(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

###################################################################################
@app.route("/",methods=['GET'])
def test():
    json = {}
    json["message"]="Server running ..."
    return jsonify(json)

def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data
if __name__=='__main__':
    dataConfig = loadFileConfig()
    print("Server running : "+"http://"+dataConfig["url-backend"]+":" + str(dataConfig["port"]))
    serve(app,host=dataConfig["url-backend"],port=dataConfig["port"])
