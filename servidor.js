const servidor = require("express")()
const cookieParser = require("cookie-parser")()
const bodyParser = require("body-parser").urlencoded({extended: false})
const aesjs = require("aes-js")
const porta = 777

const stringToBytes = (string) => aesjs.utils.utf8.toBytes(string)
const chave = stringToBytes("meupautagrandeprakrlmanoporravsf")
const encriptar = (string) => aesjs.utils.hex.fromBytes(new aesjs.ModeOfOperation.ofb(chave).encrypt(stringToBytes(string)))
const decriptar = (hex) => aesjs.utils.utf8.fromBytes(new aesjs.ModeOfOperation.ofb(chave).decrypt(aesjs.utils.hex.toBytes(hex)))
const getTimestamp = (data) => Date.parse(data.replace(/(\d{2})\/(\d{2})\/(\d{4})/, "$2/$1/$3"))

const logins = {
	"Hermit": {
		"senha": "123456",
		"info": {"banido": true, "dataAcaba": "16/04/2020"}
	},
	"timreH": {
		"senha": "654321",
		"info": {"banido": false, "dataAcaba": "15/04/2019"}
	}
}

const validarUsuario = (usuario, senha) => {
	let _usuario = logins[usuario]

	if (typeof _usuario == "undefined")
		return {status: false, message: "Usuario inexistente"}
	else if (_usuario.senha != senha)
		return {status: false, message: "Senha incorreta"}
	else if (_usuario.info.banido)
		return {status: false, message: "Esse usuario esta banido"}
	else if (getTimestamp(_usuario.info.dataAcaba) - Date.now() <= 0)
		return {status: false, message: "O tempo de uso acabou"}

	return {status: true, usuario: usuario, dados: _usuario}
}

const validarSession = (session) => {
	if (typeof session == "undefined")
		return {status: false}

	let sessionParsed = JSON.parse(decriptar(session))
	let validar = validarUsuario(sessionParsed.usuario, sessionParsed.dados.senha)
	sessionParsed.dados = validar.dados

	if (typeof sessionParsed == "undefined")
		return {status: false}
	else if (!validar.status)
		return {status: false}

	return {status: true, session: sessionParsed}
}

servidor.set("view engine", "ejs")
servidor.use(cookieParser)
servidor.use(bodyParser)
servidor.use("/login", (clienteRequest, cliente, continua) => validarSession(clienteRequest.cookies.session).status ? cliente.redirect("/") : continua() )

const paths = {
	"/": {
		GET: (clienteRequest, cliente) => {
			let validar = validarSession(clienteRequest.cookies.session)
			if(!validar.status){
				cliente.redirect("/login")
				return
			}

			cliente.render(__dirname + "/index", { usuarioSession: validar.session })
		},
		POST: () => {}
	},
	"/login": {
		GET: (clienteRequest, cliente) => {
			cliente.render(__dirname + "/login")
		},
		POST: (clienteRequest, cliente) => {
			let validar = validarUsuario(clienteRequest.body.usuario, clienteRequest.body.senha)
			if (!validar.status){
				cliente.send(JSON.stringify({status: false, message: validar.message}))
			}else{
				let sessionEncriptado = encriptar(JSON.stringify(validar))
				cliente.cookie("session", sessionEncriptado)
				cliente.send(JSON.stringify({status: true, usuario: clienteRequest.body.usuario, session: sessionEncriptado}))
			}
		}
	}
}

servidor.get(Object.keys(paths), (r, c) => paths[Object.keys(paths).filter(p => r.path == p)[0]].GET(r,c))

servidor.post(Object.keys(paths), (r, c) => paths[Object.keys(paths).filter(p => r.path == p)[0]].POST(r,c))

servidor.listen(porta, () => console.log("INICIADO NA PORTA", porta))
