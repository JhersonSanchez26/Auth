const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const expressJwt = require('express-jwt');
const { application } = require('express');
const User = require('./user');
const { findById } = require('./user');
const port = 3000;

//Conectandonos a mongodb
mongoose.connect('mongodb+srv://jhersonsanchez26:Gaby8031756..@cluster0.dku7tvb.mongodb.net/auth?retryWrites=true&w=majority');

const app = express();

app.use(express.json());

console.log(process.env.SECRET)

/*Validar Json de petición get del usuario. Antes de arrancar la app se debe correr la variable de
entorno con la siguiente ruta en la terminal: $env:SECRET = “secreto-id” y para mostrar: $env:SECRET
Si no se realiza el proceso el servidor generara un error debido a que no se tiene definida la variable 
de entorno*/

const validateJwt = expressJwt({ secret: process.env.SECRET, algorithms: ['HS256'] });

//Creamos un token usando el id del usuario registrado en mongoodb con el metodo jwt.sign ();

const singToken = _id => jwt.sign({ _id }, process.env.SECRET);

//Creando endpoint metodo post

app.post('/register', async(req, res) => {

    const { body } = req;
    console.log({ body });
    try {
        //Almacenamos en la variable isUser el objeto email con en el método findOne();
        //El método findOne(); devuelve un objeto {} ejm:
        const isUser = await User.findOne({ email: body.email });
        if (isUser) {
            return res.status(403).send('El usuario ya existe');
        }

        const salt = await bcrypt.genSalt();
        //Encryptamos la contraseña con bcrypt 
        const hashed = await bcrypt.hash(body.password, salt);
        //Creamos usuario con email y contraseña encryptada 
        const user = await User.create({ email: body.email, password: hashed, salt });
        //Opcional enviamos id de registro en mongoodb (No es una buena practica)
        //res.send({ id: user._id })

        const signed = singToken(user._id);
        // Enviamos el codigo 201 + tokend de registro de usuario
        res.status(201).send(signed);




    } catch (err) {
        console.log(err);
        //En caso de error enviamos es status codigo 500 y el error
        res.status(500).send(err.message);
    }
})

//Inicio de sesión

app.post('/login', async(req, res) => {

    const { body } = req;
    try {

        const user = await User.findOne({ email: body.email });

        if (!user) {
            res.status(403).send('Usuario y/o Contadseña incorrecta');
        } else {

            const isMatch = await bcrypt.compare(body.password, user.password);
            if (isMatch) {

                const asigned = singToken(user._id)
                res.status(200).send(asigned)
            } else {
                res.status(403).send('Usuario y/o Contadseña incorrecta');
            }
        }
    } catch (err) {
        res.status(500).send(err.message);
    }
})

// función Middleware en caso de que no se autorice el token del usuario.

const findAndAssignUser = async(req, res, next) => {

    try {

        const user = await User.findById(req.user._id);
        if (!user) {

            return res.status(401).end();
        }
        req.user = user;
        next();
    } catch (e) {

        next(e)
    }
}

// Con express.Router().use() podemos unir dos Middleware en uno ejem:
const isAuthenticated = express.Router().use(validateJwt, findAndAssignUser)

//Creación de Middleware luego de autenticación del JSON token recibida del cliente.

app.get('/protected', isAuthenticated, (req, res) => {

    res.send(req.user);
})

app.listen(port, () => {

    console.log('Arrancando la aplicación');
});