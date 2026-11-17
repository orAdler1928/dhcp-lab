try:
  import questionary

  HAS_QUESTIONARY = True
except ImportError:
  HAS_QUESTIONARY = False


def select_device(devices, server_ip, my_ip=None):
  candidates = []

  for d in devices:
    if d["ip"] != my_ip and d["ip"] != server_ip:
      candidates.append(d)


  if not candidates:
    print("[-] No other devices found on the network")
    raise RuntimeError("No other devices found on the network")

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
      raise RuntimeError("Selection cancelled")

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
  }
