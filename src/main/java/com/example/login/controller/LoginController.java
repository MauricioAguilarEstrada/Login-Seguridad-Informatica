package com.example.login.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
//Libreria de regex
import java.util.regex.Pattern;
import org.springframework.jdbc.core.JdbcTemplate;
import java.util.List;
import java.util.Random;

//librerias para enviar correos
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*") 
public class LoginController {

    // 1. Definir la Expresión Regular
        // 1. Definir la Expresión Regular
    // A) Debe contener el prefijo "DEV" al inicio
    // B) Debe contener 4 digitos despues del prefijo
    // C) Debe contener el apellido paterno del usuario empezando por mayuscula
    // D) Debe haber un guion ("-") despues de cada requisito exceptuando el ultimo
    // Ej. DEV-1234-Aguilar
    private static final String USUARIO_REGEX = "^DEV-[0-9]{4}-[A-Z][a-z]{1,12}$";
    private static final Pattern pattern = Pattern.compile(USUARIO_REGEX);

    // 2. Inyectamos JdbcTemplate a nivel de clase
    @Autowired
    private JdbcTemplate jdbcTemplate;
    @Autowired
    private JavaMailSender mailSender;

    @PostMapping("/login")
    public ResponseEntity<String> procesarLogin(@RequestBody LoginRequest request) {

        // ==========================================
        // PASO 1: Validar Usuario por Expresión Regular
        // ==========================================
        if (request.usuario() == null || !pattern.matcher(request.usuario()).matches()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Fallo en Paso 1: El formato del usuario es inválido.");
        }

        // ==========================================
        // PASO 2: Validar Clave
        // ==========================================
        String consultaClave = "SELECT claver FROM usuarios WHERE usuario = ?";
        List<String> clavesBD = jdbcTemplate.queryForList(consultaClave, String.class, request.usuario());

        //Se verifica que la lista clavesDB retorne los valores de usuario y clave, de lo contrario se retorna un http no autorizado
        if (clavesBD.isEmpty() || !clavesBD.get(0).equals(request.clave())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Fallo en Paso 2: Usuario o clave incorrectos.");
        }

        // Se genera y se guardada el código MFA
        String codigoMfa = String.format("%06d", new Random().nextInt(999999));
        
        //Se inserta el codigo creado en la bd
        String insertMfa = "INSERT INTO mfaCodigos (usuario_id, codigo, fecha_expiracion) VALUES (?, ?, NOW() + INTERVAL '5 minutes')";
        jdbcTemplate.update(insertMfa, request.usuario(), codigoMfa);

        // Envío de correo
        SimpleMailMessage mensaje = new SimpleMailMessage();
        mensaje.setTo(request.correo());
        mensaje.setSubject("Tu código de seguridad");
        mensaje.setText("Tu código de acceso es: " + codigoMfa + "\nExpira en 5 minutos.");
        mailSender.send(mensaje);

        return ResponseEntity.ok("Código enviado al correo.");

    }

    @PostMapping("/verify")
    public ResponseEntity<String> verificarMfa(@RequestBody VerifyRequest request) {
        //Validación del código contra la base de datos
        String consultaMfa = "SELECT codigo FROM mfaCodigos WHERE usuario_id = ? AND codigo = ? AND fecha_expiracion > NOW()";
        List<String> validacion = jdbcTemplate.queryForList(consultaMfa, String.class, request.usuario(), request.codigo());

        if (validacion.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Código incorrecto o expirado.");
        }

        // Eliminación del código tras un uso exito
        jdbcTemplate.update("DELETE FROM mfaCodigos WHERE usuario_id = ?", request.usuario());

        return ResponseEntity.ok("Acceso final concedido.");
    }
}


// Estructura (DTO)
record LoginRequest(String usuario, String clave, String correo) {}
record VerifyRequest(String usuario, String codigo) {}

