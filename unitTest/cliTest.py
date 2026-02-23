import pytest
import os
from click.testing import CliRunner
from lcsajdump.cli import main

def test_cli_help():
    """Verifica che il menu di help si apra correttamente e non crashi."""
    runner = CliRunner()
    result = runner.invoke(main, ['--help'])
    assert result.exit_code == 0
    # Aggiornato con la stringa reale del tuo help
    assert "LCSAJ ROP Finder" in result.output

def test_cli_missing_file():
    """Verifica la gestione degli errori quando si passa un file inesistente."""
    runner = CliRunner()
    result = runner.invoke(main, ['file_che_non_esiste.bin'])
    assert result.exit_code != 0

def test_cli_invalid_arch():
    """Verifica che un'architettura non supportata venga bloccata."""
    runner = CliRunner()
    
    # Creiamo un file temporaneo reale così supera il controllo path di Click
    with runner.isolated_filesystem():
        with open('fake_binary.bin', 'w') as f:
            f.write('dummy data')
            
        result = runner.invoke(main, ['fake_binary.bin', '--arch', 'arch_inventata'])
        
        # Ci aspettiamo che il programma fallisca (exit code diverso da 0)
        assert result.exit_code != 0
        
        # Verifichiamo che il BinaryLoader abbia sollevato l'eccezione corretta
        assert isinstance(result.exception, ValueError)
        assert "Architettura arch_inventata non supportata" in str(result.exception)
