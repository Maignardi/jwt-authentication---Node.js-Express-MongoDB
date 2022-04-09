require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

app.use(express.json())

const User = require('./models/User')

app.get('/', (req, res) =>{
    res.status(200).json({msg: "Bem vindo a nossa API"})
})

app.get("/user/:id", checkToken, async(req, res) =>{
    
    const id = req.params.id

    const user = await User.findById(id, "-password")

    if(!user){
        return res.status(404).json({ msg: "Usuario nao encontrado" })
    }

    res.status(200).json({ user })

})

function checkToken(req, res, next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token){
        return res.status(401).json({ msg: "Acesso Negado!" })
    }

    try{

        const secret = process.env.SECRET
        jwt.verify(token, secret)
        next()

    }catch(error){
        res.status(400).json({ msg: "Token Invalido!" })
    }

}

app.post('/auth/register', async(req, res) => {

    const {name, email, password, confirmpassword} = req.body

    if(!name || !email || !password){
        return res.status(422).json({msg: "Credenciais obrigatorias!"})
    }

    if(password !== confirmpassword){
        return res.status(422).json({ msg: 'As senhas sao diferentes!' })
    }

    const userExist = await User.findOne({email: email})

    if(userExist){
        return res.status(422).json({ msg: 'Por favor, utilize outro email!' })
    }

    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    const user = new User({
        name,email,password: passwordHash,
    })

    try{

        await user.save()

        res.status(201).json({ msg: "Usuario criado com sucesso" })

    }catch(error){

        console.log(error)
        res.status(500).json("Aconteceu um error")
        
    }

})

app.post("/auth/login", async (req, res) =>{

    const {email, password} = req.body

    if(!password || !email){
        return res.status(422).json({msg: "Credenciais obrigatorias!"})
    }

    const user = await User.findOne({email: email})

    if(!user){
        return res.status(404).json({ msg: 'Usuario nao encontrado!' })
    }

    const checkPassword = await bcrypt.compare(password, user.password)

    if(!checkPassword){
        return res.status(422).json({ msg: 'Senha invalida!' })
    }

    try{

        const secret = process.env.SECRET
        const token = jwt.sign({
            id: user._id,
        }, secret,)

        res.status(200).json({ msg: "Autenticaçao com sucesso", token })


    }catch(error){

        console.log(error)
        res.status(500).json("Aconteceu um error")
        
    }

})

const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.gji4m.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`).then( () => {
    app.listen(3000)
    console.log('Conectou com o banco')
}).catch((err) => console.log(err))
