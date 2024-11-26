package com.autobots.automanager.jwt;

import java.util.Date;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

class GeradorJwt {

	private String assinatura;
	private Date expiracao;

	public GeradorJwt(String assinatura, long duracao) {
		if (assinatura == null || assinatura.isEmpty()) {
			throw new IllegalArgumentException("A chave de assinatura não pode ser nula ou vazia.");
		}
		if (duracao <= 0) {
			throw new IllegalArgumentException("A duração do token deve ser maior que zero.");
		}

		this.assinatura = assinatura;
		this.expiracao = new Date(System.currentTimeMillis() + duracao);
	}

	public String gerarJwt(String nomeUsuario) {
		if (nomeUsuario == null || nomeUsuario.isEmpty()) {
			throw new IllegalArgumentException("O nome de usuário não pode ser nulo ou vazio.");
		}

		return Jwts.builder()
				.setSubject(nomeUsuario)  // Define o nome do usuário como sujeito do JWT
				.setExpiration(this.expiracao)  // Define a data de expiração do token
				.signWith(SignatureAlgorithm.HS512, this.assinatura.getBytes())  // Assina o JWT com a chave
				.compact();  // Gera o token compactado
	}
}
