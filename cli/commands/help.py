from cli.views.console import console


def show_help():

    console.print("\n[bold orange1]Available commands:[/bold orange1]")
    console.print(
        "  [cyan]/scan <path>[/cyan]     Run a standard security scan without fixing."
    )
    console.print(
        "  [cyan]/auto-fix <path>[/cyan] Run a scan and automatically fix vulnerabilities using AI."
    )
    console.print("  [cyan]/help[/cyan]            Show this help message.")
    console.print("  [cyan]/exit[/cyan]            Exit the CLI.\n")
