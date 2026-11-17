try:
  import questionary

  HAS_QUESTIONARY = True
except ImportError:
  HAS_QUESTIONARY = False


def select_device(devices, server_ip, my_ip=None):
  server_mac = None
  candidates = []

  for d in devices:
    if d["ip"] == server_ip:
      server_mac = d["mac"]
    elif d["ip"] != my_ip:
      candidates.append(d)

  if server_mac is None:
    print(f"[-] Server {server_ip} not found in scan results")
    return None

  if not candidates:
    print("[-] No other devices found on the network")
    return None

  selected = None

  if HAS_QUESTIONARY:
    choices = [
        questionary.Choice(title=f"{d['ip']:<16} ({d['mac']})", value=d)
        for d in candidates
    ]

    selected = questionary.select(
        "Select target device:",
        choices=choices,
        use_indicator=True,  
    ).ask()


    if selected is None:
      print("[-] Selection cancelled.")
      return None

  else:
    print("\nAvailable devices:")
    for idx, d in enumerate(candidates, start=1):
      print(f"[{idx}] {d['ip']:<16} ({d['mac']})")

    while True:
      try:
        choice = int(input("\nSelect target device number: "))
        if 1 <= choice <= len(candidates):
          selected = candidates[choice - 1]
          break
        print("Invalid number, try again.")
      except ValueError:
        print("Please enter a valid number.")

  return {
      "target_ip": selected["ip"],
      "target_mac": selected["mac"],
      "server_mac": server_mac,
  }
