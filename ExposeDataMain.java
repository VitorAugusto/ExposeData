package DataBreach;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.Function;
import java.util.stream.Collectors;

//Biblioteca JAVA para acesso à API do Have i Been Pwned.
import de.martinspielmann.haveibeenpwned4j.HaveIBeenPwnedApiClient;
import de.martinspielmann.haveibeenpwned4j.model.Breach;

public class ExposeDataMain {

	static String ignoreEmail = "Email addresses";
	static String ignorePassword = "Passwords";
	// Chave de API necessária para realizar consultas na base de dados.
	static String minhaApiKey = "~~~~~~";

	public static void main(String[] args) throws IOException {
		// Lista de e-mails para pesquisa.
		List<String> amostraEmails = new ArrayList<String>();

		amostraEmails.add("-----EMAIL OCULTO-----"); // email 1
		amostraEmails.add("-----EMAIL OCULTO-----"); // email 2
		amostraEmails.add("-----EMAIL OCULTO-----"); // email 3
		amostraEmails.add("-----EMAIL OCULTO-----"); // email 4
		amostraEmails.add("-----EMAIL OCULTO-----"); // email 5
		amostraEmails.add("-----EMAIL OCULTO-----"); // email 6
		amostraEmails.add("-----EMAIL OCULTO-----"); // email 7
		amostraEmails.add("-----EMAIL OCULTO-----"); // email 8
		amostraEmails.add("-----EMAIL OCULTO-----"); // email 9
		amostraEmails.add("-----EMAIL OCULTO-----"); // email 10

		int INDICE_CONTA = 0; // Índice da conta de e-mail a ser analisada.

		HaveIBeenPwnedApiClient cliente = new HaveIBeenPwnedApiClient(minhaApiKey);

		// Lista todas as violações de dados da respectiva conta.
		List<Breach> allBreaches = cliente.getBreachesForAccount(amostraEmails.get(INDICE_CONTA));

		// Conjunto de procedimentos que buscam os dados e exibem as informações.
		if (allBreaches.size() != 0) {
			int numViolacoes = getNumeroViolacoes(allBreaches);
			System.out.println("Email : " + amostraEmails.get(INDICE_CONTA));
			System.out.println("Vazamentos sofridos: " + numViolacoes);
			System.out.println("Média de ano das violações sofridas : " + getMediaAritmetica(allBreaches));
			int pesoAno = getPesoAno(allBreaches);
			int somaNumDadosTotal = somaNumDadosTotal(allBreaches);
			int somaNumDadosIgnoEmailSenha = somaNumDadosIgnorandoEmailSenha(allBreaches);

			System.out.println("NÚMERO DE DADOS VIOLADOS, Ignorando tupla Email/Senha : " + somaNumDadosIgnoEmailSenha);
			System.out.println("NÚMERO DE DADOS VIOLADOS, Total:  " + somaNumDadosTotal);
			System.out.println("\n");

			int scoreExposicao = getScoreTotalExposicao(numViolacoes, somaNumDadosIgnoEmailSenha, pesoAno);
			System.out.println("Score / Nível de exposição : " + scoreExposicao);

			getStatusFromScoreExposicao(scoreExposicao);

		} else {
			System.out.println("Email : " + amostraEmails.get(INDICE_CONTA));
			System.out.println("Usuário não possui violações.");
		}

		System.out.println("\n");

		List<String> listaAllTiposDadosViolados = getAllTiposDadosViolados(allBreaches);

		// Agrupo por frequência - Lista de todos os tipos de dados violados
		Map<String, Long> frequencyMap = listaAllTiposDadosViolados.stream()
				.collect(Collectors.groupingBy(Function.identity(), Collectors.counting()));

		// Ordeno do MAIOR para o Menor a lista de todos os tipos de dados violados
		Map<String, Long> sortedMap = frequencyMap.entrySet().stream()
				.sorted(Entry.<String, Long>comparingByValue().reversed())
				.collect(Collectors.toMap(Entry::getKey, Entry::getValue, (e1, e2) -> e1, LinkedHashMap::new));
	}

	// Função que realiza a soma do número de dados violados - ignorando Email e
	// Senha.
	public static int somaNumDadosIgnorandoEmailSenha(List<Breach> lista) {
		int valorSoma = 0;

		for (int i = 0; i < lista.size(); i++) {

			Breach vazamentoAtual = lista.get(i);
			List<String> listaDadosVazamentoAtual = vazamentoAtual.getDataClasses();

			for (int j = 0; j < vazamentoAtual.getDataClasses().size(); j++) {

				if (!listaDadosVazamentoAtual.get(j).toString().equals(ignoreEmail)
						&& !listaDadosVazamentoAtual.get(j).toString().equals(ignorePassword)) {
					valorSoma += 1;
				}
			}
		}

		return valorSoma;
	}

	// Função que realiza a soma do número total de dados violados.
	public static int somaNumDadosTotal(List<Breach> lista) {
		int valorSoma = 0;

		for (int i = 0; i < lista.size(); i++) {

			Breach vazamentoAtual = lista.get(i);
			List<String> listaDadosVazamentoAtual = vazamentoAtual.getDataClasses();

			for (int j = 0; j < vazamentoAtual.getDataClasses().size(); j++) {

				valorSoma += 1;
			}
		}

		return valorSoma;
	}

	// Função que retorna o número de violações de uma lista.
	public static int getNumeroViolacoes(List<Breach> lista) {
		return (lista.size());
	}

	// Função que retorna a soma do ano das violações.
	public static int getSomaAnoViolacoes(List<Breach> lista) {
		int somaAnoViolacoes = 0;

		for (int i = 0; i < lista.size(); i++) {
			somaAnoViolacoes += lista.get(i).getBreachDate().getYear();
		}

		return somaAnoViolacoes;
	}

	// Função que retorna a Média aritmética ponderada da lista de violações.
	public static float getMediaAritmetica(List<Breach> lista) {
		float mediaAritmetica = 0;
		mediaAritmetica = getSomaAnoViolacoes(lista) / getNumeroViolacoes(lista);
		return mediaAritmetica;
	}

	// Função que retorna o Peso por Ano das violações, de acordo com a média
	// aritmética.
	public static int getPesoAno(List<Breach> lista) {
		int pesoAno = 0;
		float mediaAritmetica = getMediaAritmetica(lista);

		if (mediaAritmetica <= 2010) {
			pesoAno = 5;
		} else if (mediaAritmetica > 2010 && mediaAritmetica <= 2015) {
			pesoAno = 10;
		} else if (mediaAritmetica > 2015 && mediaAritmetica <= 2020) {
			pesoAno = 20;
		} else if (mediaAritmetica > 2020) {
			pesoAno = 30;
		}

		return pesoAno;
	}

	// Função que realiza o cálculo do score de exposição.
	public static int getScoreTotalExposicao(int numViolacoes, int numDadosIgnorandoEmailSenha, int pesoAno) {
		return (numViolacoes + numDadosIgnorandoEmailSenha + pesoAno);
	}

	// Função que retorna a classificação, de acordo com o score de exposição
	public static void getStatusFromScoreExposicao(int score) {
		if (score > 0 && score <= 25) {
			System.out.println("Menos Exposto");
		} else if (score > 25 && score <= 50) {
			System.out.println("Mais exposto");
		} else if (score > 50) {
			System.out.println("Estado Crítico");
		}
	}

	// Retorna uma lista com todos os tipos diferentes de dados violados.
	public static List<String> getAllTiposDadosViolados(List<Breach> lista) {

		List<String> listaDadosViolados = new ArrayList<String>();

		for (int i = 0; i < lista.size(); i++) {

			List<String> dadosViolados = lista.get(i).getDataClasses();

			for (int j = 0; j < dadosViolados.size(); j++) {

				listaDadosViolados.add(dadosViolados.get(j).toString());

			}
		}

		return listaDadosViolados;
	}

}
