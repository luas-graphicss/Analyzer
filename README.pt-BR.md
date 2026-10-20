# ByteGuard Analyzer

[Read in English](README.md)

O ByteGuard é um analisador estático de arquivos escrito em Python. Você entrega um arquivo e ele diz se existe algo suspeito ali dentro, sem nunca executar o arquivo. Ele funciona totalmente offline e usa só a biblioteca padrão do Python, então não tem nada extra para instalar.

Ele abre contêineres como arquivos compactados e documentos PDF e XML, percorre o conteúdo procurando sinais de risco e depois entrega um relatório com cada achado e a gravidade dele. Tudo é limitado de propósito. Existem limites para o tamanho do arquivo, para a profundidade dentro de contêineres aninhados, para a taxa de descompressão, para a quantidade de membros, para o total de bytes e para o tempo de processamento, e a análise roda num worker separado com limite de memória nos sistemas que suportam isso. Assim um arquivo malicioso feito para explodir de tamanho ou travar o analisador não derruba a máquina junto.

O relatório pode sair em texto, JSON ou SARIF 2.1.0, que conversa com ferramentas de segurança e pipelines de CI. Também dá para comparar o arquivo com um SHA-256 de uma fonte confiável e usar uma lista de bloqueio com hashes conhecidos. O programa termina com código 1 quando o risco chega no nível escolhido, que por padrão é alto.

Também tem uma interface desktop simples para quem prefere não usar o terminal.

## Como usar

Você precisa do Python 3.11 ou mais novo. O jeito mais fácil é rodar python run.py, que abre a interface desktop. Para usar pelo terminal, instale com o pip a partir da pasta do repositório e o comando byteguard fica disponível. Depois é só rodar byteguard seguido do caminho do arquivo. O byteguard --help lista todas as opções, como o formato do relatório, o arquivo de saída e todos os limites. A interface desktop também abre com byteguard --gui ou com o comando byteguard-desktop.

## Tempo de desenvolvimento

O ByteGuard foi feito em duas horas.

## Licença

GNU General Public License versão 3. O texto completo está no arquivo LICENSE.
