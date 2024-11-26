package com.autobots.automanager;

import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.autobots.automanager.entidades.CredencialUsuarioSenha;
import com.autobots.automanager.entidades.Documento;
import com.autobots.automanager.entidades.Email;
import com.autobots.automanager.entidades.Empresa;
import com.autobots.automanager.entidades.Endereco;
import com.autobots.automanager.entidades.Mercadoria;
import com.autobots.automanager.entidades.Servico;
import com.autobots.automanager.entidades.Telefone;
import com.autobots.automanager.entidades.Usuario;
import com.autobots.automanager.entidades.Veiculo;
import com.autobots.automanager.entidades.Venda;
import com.autobots.automanager.enumeracoes.PerfilUsuario;
import com.autobots.automanager.enumeracoes.TipoDocumento;
import com.autobots.automanager.enumeracoes.TipoVeiculo;
import com.autobots.automanager.repositorios.EmpresaRepositorio;

@SpringBootApplication
public class AutomanagerApplication implements CommandLineRunner {

	BCryptPasswordEncoder codificador = new BCryptPasswordEncoder();

	@Autowired
	private EmpresaRepositorio repositorioEmpresa;
	

	public static void main(String[] args) {
		SpringApplication.run(AutomanagerApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {

		Empresa empresa = new Empresa();
		empresa.setRazaoSocial("Car service toyota ltda");
		empresa.setNomeFantasia("Car service manutenção veicular");
		empresa.setCadastro(new Date());

		Endereco enderecoEmpresa = new Endereco();
		enderecoEmpresa.setEstado("São Paulo");
		enderecoEmpresa.setCidade("São Paulo");
		enderecoEmpresa.setBairro("Centro");
		enderecoEmpresa.setRua("Av. São João");
		enderecoEmpresa.setNumero("00");
		enderecoEmpresa.setCodigoPostal("01035-000");

		empresa.setEndereco(enderecoEmpresa);

		Telefone telefoneEmpresa = new Telefone();
		telefoneEmpresa.setDdd("011");
		telefoneEmpresa.setNumero("986454527");

		empresa.getTelefones().add(telefoneEmpresa);

		Usuario funcionario = new Usuario();
		funcionario.setNome("Pedro Alcântara de Bragança e Bourbon");
		funcionario.setNomeSocial("Dom Pedro");
		funcionario.getPerfis().add(PerfilUsuario.ROLE_VENDEDOR);

		Email emailFuncionario = new Email();
		emailFuncionario.setEndereco("a@a.com");

		funcionario.getEmails().add(emailFuncionario);

		Endereco enderecoFuncionario = new Endereco();
		enderecoFuncionario.setEstado("São Paulo");
		enderecoFuncionario.setCidade("São Paulo");
		enderecoFuncionario.setBairro("Jardins");
		enderecoFuncionario.setRua("Av. São Gabriel");
		enderecoFuncionario.setNumero("00");
		enderecoFuncionario.setCodigoPostal("01435-001");

		funcionario.setEndereco(enderecoFuncionario);

		empresa.getUsuarios().add(funcionario);

		Telefone telefoneFuncionario = new Telefone();
		telefoneFuncionario.setDdd("011");
		telefoneFuncionario.setNumero("9854633728");

		funcionario.getTelefones().add(telefoneFuncionario);

		Documento cpf = new Documento();
		cpf.setDataEmissao(new Date());
		cpf.setNumero("856473819229");
		cpf.setTipo(TipoDocumento.CPF);

		funcionario.getDocumentos().add(cpf);

		CredencialUsuarioSenha credencialFuncionario = new CredencialUsuarioSenha();
		credencialFuncionario.setInativo(false);
		credencialFuncionario.setNomeUsuario("dompedrofuncionario");
		credencialFuncionario.setSenha(codificador.encode("123456"));
		credencialFuncionario.setCriacao(new Date());
		credencialFuncionario.setUltimoAcesso(new Date());

		funcionario.getCredenciais().add(credencialFuncionario);

		Usuario fornecedor = new Usuario();
		fornecedor.setNome("Componentes varejo de partes automotivas ltda");
		fornecedor.setNomeSocial("Loja do carro, vendas de componentes automotivos");
		fornecedor.getPerfis().add(PerfilUsuario.ROLE_FORNECEDOR);

		Email emailFornecedor = new Email();
		emailFornecedor.setEndereco("f@f.com");

		fornecedor.getEmails().add(emailFornecedor);

		CredencialUsuarioSenha credencialFornecedor = new CredencialUsuarioSenha();
		credencialFornecedor.setInativo(false);
		credencialFornecedor.setNomeUsuario("dompedrofornecedor");
		credencialFornecedor.setSenha(codificador.encode("123456"));
		credencialFornecedor.setCriacao(new Date());
		credencialFornecedor.setUltimoAcesso(new Date());

		fornecedor.getCredenciais().add(credencialFornecedor);

		Documento cnpj = new Documento();
		cnpj.setDataEmissao(new Date());
		cnpj.setNumero("00014556000100");
		cnpj.setTipo(TipoDocumento.CNPJ);

		fornecedor.getDocumentos().add(cnpj);

		Endereco enderecoFornecedor = new Endereco();
		enderecoFornecedor.setEstado("Rio de Janeiro");
		enderecoFornecedor.setCidade("Rio de Janeiro");
		enderecoFornecedor.setBairro("Centro");
		enderecoFornecedor.setRua("Av. República do chile");
		enderecoFornecedor.setNumero("00");
		enderecoFornecedor.setCodigoPostal("20031-170");

		fornecedor.setEndereco(enderecoFornecedor);

		empresa.getUsuarios().add(fornecedor);
		
		Mercadoria rodaLigaLeve = new Mercadoria();
		rodaLigaLeve.setCadastro(new Date());
		rodaLigaLeve.setFabricao(new Date());
		rodaLigaLeve.setNome("Roda de liga leva modelo toyota etios");
		rodaLigaLeve.setValidade(new Date());
		rodaLigaLeve.setQuantidade(30);
		rodaLigaLeve.setValor(300.0);
		rodaLigaLeve.setDescricao("Roda de liga leve original de fábrica da toyta para modelos do tipo hatch");

		empresa.getMercadorias().add(rodaLigaLeve);

		fornecedor.getMercadorias().add(rodaLigaLeve);

		Usuario cliente = new Usuario();
		cliente.setNome("Pedro Alcântara de Bragança e Bourbon");
		cliente.setNomeSocial("Dom pedro cliente");
		cliente.getPerfis().add(PerfilUsuario.ROLE_CLIENTE);

		Email emailCliente = new Email();
		emailCliente.setEndereco("c@c.com");

		cliente.getEmails().add(emailCliente);

		Documento cpfCliente = new Documento();
		cpfCliente.setDataEmissao(new Date());
		cpfCliente.setNumero("12584698533");
		cpfCliente.setTipo(TipoDocumento.CPF);

		cliente.getDocumentos().add(cpfCliente);

		CredencialUsuarioSenha credencialCliente = new CredencialUsuarioSenha();
		credencialCliente.setInativo(false);
		credencialCliente.setNomeUsuario("dompedrocliente");
		credencialCliente.setSenha(codificador.encode("123456"));
		credencialCliente.setCriacao(new Date());
		credencialCliente.setUltimoAcesso(new Date());

		cliente.getCredenciais().add(credencialCliente);

		Endereco enderecoCliente = new Endereco();
		enderecoCliente.setEstado("São Paulo");
		enderecoCliente.setCidade("São José dos Campos");
		enderecoCliente.setBairro("Centro");
		enderecoCliente.setRua("Av. Dr. Nelson D'Ávila");
		enderecoCliente.setNumero("00");
		enderecoCliente.setCodigoPostal("12245-070");

		cliente.setEndereco(enderecoCliente);
		
		Veiculo veiculo = new Veiculo();
		veiculo.setPlaca("ABC-0000");
		veiculo.setModelo("corolla-cross");
		veiculo.setTipo(TipoVeiculo.SUV);
		veiculo.setProprietario(cliente);
		
		cliente.getVeiculos().add(veiculo);
		
		empresa.getUsuarios().add(cliente);

		Servico trocaRodas = new Servico();
		trocaRodas.setDescricao("Troca das rodas do carro por novas");
		trocaRodas.setNome("Troca de rodas");
		trocaRodas.setValor(50);

		Servico alinhamento = new Servico();
		alinhamento.setDescricao("Alinhamento das rodas do carro");
		alinhamento.setNome("Alinhamento de rodas");
		alinhamento.setValor(50);

		empresa.getServicos().add(trocaRodas);
		

		Venda venda = new Venda();
		venda.setCadastro(new Date());
		venda.setCliente(cliente);
		venda.getMercadorias().add(rodaLigaLeve);
		venda.setIdentificacao("1234698745");
		venda.setVendedor(funcionario);
		venda.getServicos().add(trocaRodas);
		venda.getServicos().add(alinhamento);
		venda.setVeiculo(veiculo);
		veiculo.getVendas().add(venda);

		empresa.getVendas().add(venda);

		repositorioEmpresa.save(empresa);
		
		Mercadoria rodaLigaLeve2 = new Mercadoria();
		rodaLigaLeve2.setCadastro(new Date());
		rodaLigaLeve2.setFabricao(new Date());
		rodaLigaLeve2.setNome("Roda de liga pesada modelo toyota yaris");
		rodaLigaLeve2.setValidade(new Date());
		rodaLigaLeve2.setQuantidade(30);
		rodaLigaLeve2.setValor(300.0);
		rodaLigaLeve2.setDescricao("Roda de liga pesada original de fábrica da toyta para modelos do tipo hatch");
		
		Servico alinhamento2 = new Servico();
		alinhamento2.setDescricao("Alinhamento das rodas do carro");
		alinhamento2.setNome("Alinhamento de rodas");
		alinhamento2.setValor(50);
		
		Servico balanceamento = new Servico();
		balanceamento.setDescricao("balanceamento das rodas do carro");
		balanceamento.setNome("balanceamento de rodas");
		balanceamento.setValor(30);
		
		Venda venda2 = new Venda();
		venda2.setCadastro(new Date());
		venda2.setCliente(cliente);
		venda2.getMercadorias().add(rodaLigaLeve2);
		venda2.setIdentificacao("1234698749");
		venda2.setVendedor(funcionario);
		venda2.getServicos().add(balanceamento);
		venda2.getServicos().add(alinhamento2);
		venda2.setVeiculo(veiculo);
		veiculo.getVendas().add(venda2);

		empresa.getVendas().add(venda2);
		
		Usuario adm = new Usuario();
		adm.setNome("ADM");
		adm.setNomeSocial("Jonas Oliveira");
		adm.getPerfis().add(PerfilUsuario.ROLE_ADMIN);

		Email emailAdm = new Email();
		emailAdm.setEndereco("jonasMiguel@gmail.com");

		funcionario.getEmails().add(emailAdm);

		Endereco enderecoAdm = new Endereco();
		enderecoAdm.setEstado("São Paulo");
		enderecoAdm.setCidade("São Paulo");
		enderecoAdm.setBairro("florida");
		enderecoAdm.setRua("janeiro");
		enderecoAdm.setNumero("123");
		enderecoAdm.setCodigoPostal("78965-452");

		adm.setEndereco(enderecoAdm);

		empresa.getUsuarios().add(funcionario);

		Telefone telefoneAdm = new Telefone();
		telefoneAdm.setDdd("011");
		telefoneAdm.setNumero("991099999");

		adm.getTelefones().add(telefoneAdm);

		Documento passaporte = new Documento();
		passaporte.setDataEmissao(new Date());
		passaporte.setNumero("1234567");
		passaporte.setTipo(TipoDocumento.PASSAPORTE);

		adm.getDocumentos().add(passaporte);

		CredencialUsuarioSenha credencialAdm = new CredencialUsuarioSenha();
		credencialAdm.setInativo(false);
		credencialAdm.setNomeUsuario("Roberto");
		credencialAdm.setSenha(codificador.encode("123"));
		credencialAdm.setCriacao(new Date());
		credencialAdm.setUltimoAcesso(new Date());

		adm.getCredenciais().add(credencialAdm);
		
		empresa.getUsuarios().add(adm);
		
		repositorioEmpresa.save(empresa);
	}
}