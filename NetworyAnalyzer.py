# Importing required libraries
import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
import networkx as nx
import geoip2.database
import pyfiglet
from pyvis.network import Network

# Cross-platform compatibility
def clear_screen():
    """Clear screen for both Windows and Unix systems"""
    os.system('cls' if os.name == 'nt' else 'clear')

def pause_screen():
    """Pause screen for both Windows and Unix systems"""
    if os.name == 'nt':  # Windows
        os.system('pause')
    else:  # Unix/Linux/Mac
        input("Press Enter to continue...")

def banner():
    try:
        result = pyfiglet.figlet_format("Priyanshu's Network Analyzer", font = "slant" ) 
        print(result)
    except Exception as e:
        print("=" * 50)
        print("Priyanshu's Network Analyzer")
        print("=" * 50)

def menu2(data_file):
    while True:
        clear_screen()
        banner()
        print("0. Go Back")
        print("1. Show Data")
        print("2. Build Graphs")
        print("3. Trace Suspected Address")
        print("4. Find public IP address GeoLocation")
        try:
            option_menu2 = int(input("Choose an option: \n"))
        except ValueError:
            clear_screen()
            print("Invalid input given. Please enter a number.")
            pause_screen()
            clear_screen()
            continue
        if option_menu2 == 1:
            clear_screen()
            show_data(data_file)
            break
        elif option_menu2 == 2:
            clear_screen()
            graph_data(data_file)
            break
        elif option_menu2 == 3:
            clear_screen()
            suspect(data_file)
            break
        elif option_menu2 == 4:
            clear_screen()
            GeoLoc(data_file)
            break
        elif option_menu2 == 0:
            clear_screen()
            start_screen()
            break
        else:
            clear_screen()
            print("Invalid input given. Please try again.")
            pause_screen()
            clear_screen()

def show_data(data_file):
    while True:
        clear_screen()
        banner()
        print("0. Go Back")  
        print("1. Show first 10 readings")
        print("2. Show source and counts")
        print("3. Show destination and counts")
        print("4. Show protocols and counts")
        print("5. Show all traffic of a protocol")
        try:
            sub_option2 = int(input("Choose option: "))
        except ValueError:
            clear_screen()
            print("Invalid input given. Please enter a number.")
            pause_screen()
            clear_screen()
            continue
        if sub_option2 == 1:
            try:
                print(data_file.head(10))
            except KeyError:
                clear_screen()
                banner()
                print("Invalid CSV Format provided. Please upload a valid CSV file of Wireshark export format.")
                pause_screen()
                clear_screen()
                start_screen()
                return
            pause_screen()
            clear_screen()
        elif sub_option2 == 2:
            try:
                sources = data_file.groupby("Source").Source.count()
                print(sources.sort_values())
            except KeyError:
                clear_screen()
                banner()
                print("Invalid CSV Format provided. Please upload a valid CSV file of Wireshark export format.")
                pause_screen()
                clear_screen()
                start_screen()
                return
            pause_screen()
            clear_screen()
        elif sub_option2 == 3:
            try:
                dest = data_file.groupby("Destination").Destination.count()
                print(dest.sort_values())
            except KeyError:
                clear_screen()
                banner()
                print("Invalid CSV Format provided. Please upload a valid CSV file of Wireshark export format.")
                pause_screen()
                clear_screen()
                start_screen()
                return
            pause_screen()
            clear_screen()
        elif sub_option2 == 4:
            try:
                protocol = data_file.groupby("Protocol").Protocol.count()
                print(protocol.sort_values())
            except KeyError:
                clear_screen()
                banner()
                print("Invalid CSV Format provided. Please upload a valid CSV file of Wireshark export format.")
                pause_screen()
                clear_screen()
                start_screen()
                return
            pause_screen()
            clear_screen()
        elif sub_option2 == 5:
            try:
                ProtoSearch = input("Enter the protocol you want to search (case sensitive): ")
                pd.set_option('display.max_rows', 500)
                print(data_file.loc[data_file['Protocol'] == ProtoSearch, ["Time", "Source", "Destination", "Protocol", "Length"]])
                pd.set_option('display.max_rows', 10)
            except KeyError:
                clear_screen()
                banner()
                print("Invalid CSV Format provided. Please upload a valid CSV file of Wireshark export format.")
                pause_screen()
                clear_screen()
                start_screen()
                return
            pause_screen()
            clear_screen()
        elif sub_option2 == 0:
            clear_screen()
            menu2(data_file)
            break
        else:
            clear_screen()
            print("Invalid input given. Please try again.")
            pause_screen()
            clear_screen()

def graph_data(data_file):
    while True:
        clear_screen()
        banner()
        print("0. Go Back")
        print("1. Display NodeView of traffic")
        print("2. Display EdgeView of traffic")
        print("3. Display network map based on traffic")
        print("4. Display bar graph based on protocol")
        try:
            sub2_option2 = int(input("Choose an option:"))
        except ValueError:
            clear_screen()
            print("Invalid input given. Please enter a number.")
            pause_screen()
            clear_screen()
            continue
        if sub2_option2 == 1:
            try:
                network = nx.from_pandas_edgelist(data_file, source="Source", target="Destination", edge_attr=True)
                print(network.nodes())
            except Exception as e:
                print(f"Error creating network graph: {e}")
            pause_screen()
            clear_screen()
        elif sub2_option2 == 2:
            try:
                network = nx.from_pandas_edgelist(data_file, source="Source", target="Destination", edge_attr=True)
                print(network.edges())
            except Exception as e:
                print(f"Error creating network graph: {e}")
            pause_screen()
            clear_screen()
        elif sub2_option2 == 3:
            try:
                network = nx.from_pandas_edgelist(data_file, source="Source", target="Destination", edge_attr=True)
                try:
                    graph_option = int(input("\n1. Show dynamic graph in HTML View.\n2. Show image graph (.png): "))
                except ValueError:
                    clear_screen()
                    print("Invalid input given. Please enter a number.")
                    pause_screen()
                    clear_screen()
                    continue
                if graph_option == 1:
                    try:
                        net = Network(notebook=False, height='1000px', width='1500px')
                        net.from_nx(network)
                        dirname = os.path.dirname(__file__)
                        filename = os.path.join(dirname, 'networkgraph.html')
                        net.show(filename)
                        print(f"Network graph saved as: {filename}")
                    except Exception as e:
                        print(f"Error creating HTML graph: {e}")
                    pause_screen()
                    clear_screen()
                elif graph_option == 2:
                    try:
                        nx.draw_circular(network, with_labels=True)
                        plt.show()
                    except Exception as e:
                        print(f"Error displaying graph: {e}")
                    pause_screen()
                    clear_screen()
                else:
                    clear_screen()
                    print("Invalid input given. Please try again.")
                    pause_screen()
                    clear_screen()
            except Exception as e:
                print(f"Error creating network graph: {e}")
                pause_screen()
                clear_screen()
        elif sub2_option2 == 4:
            try:
                protocol = data_file.groupby("Protocol").Protocol.count()
                x = list(protocol.index)
                y = list(protocol.values)
                plt.bar(x, y, width=0.5, color='red')
                plt.plot(x, y, marker='o', color='black')
                plt.xlabel('Protocol')
                plt.ylabel('Communications')
                plt.title('No. of Communications per Protocol')
                plt.xticks(rotation=45)
                plt.tight_layout()
                plt.show()
            except Exception as e:
                print(f"Error creating bar graph: {e}")
            pause_screen()
            clear_screen()
        elif sub2_option2 == 0:
            clear_screen()
            menu2(data_file)
            break
        else:
            clear_screen()
            print("Invalid input given. Please try again.")
            pause_screen()
            clear_screen()

def suspect(data_file):
    clear_screen()
    banner()
    suspect_ad = input("Enter suspected address: ")
    print("Suspect loaded\n")
    try:
        network = nx.from_pandas_edgelist(data_file, source="Source", target="Destination", edge_attr=True)
        suspect_source_info = data_file.loc[data_file["Source"] == suspect_ad]
        suspect_dest_info = data_file.loc[data_file["Destination"] == suspect_ad]
        print("Captured source network information of suspect: \n", suspect_source_info)
        print("\n\nCaptured destination network information of suspect: \n", suspect_dest_info)
        suspect_graph_option = input("\nPress Y to show suspect network graph (any other key to go back): ")
        if suspect_graph_option.lower() == 'y':
            try:
                pos = nx.spring_layout(network)
                nx.draw(network, pos, node_color="green", node_size=300, with_labels=True)
                options = {"node_size": 1000, "node_color": "r"}
                nx.draw_networkx_nodes(network, pos, nodelist=[suspect_ad], **options)
                plt.show()
                pause_screen()
                clear_screen()
                menu2(data_file)
            except nx.exception.NetworkXError:
                clear_screen()
                banner()
                print("Suspect not in network. Please try again.")
                pause_screen()
                clear_screen()
                menu2(data_file)
            except Exception as e:
                print(f"Error displaying suspect graph: {e}")
                pause_screen()
                clear_screen()
                menu2(data_file)
        else:
            clear_screen()
            menu2(data_file)
    except Exception as e:
        print(f"Error processing suspect data: {e}")
        pause_screen()
        clear_screen()
        menu2(data_file)

def GeoLoc(data_file):
    clear_screen()
    banner()
    print("\n GEOLOCATION TOOL: \nFinds country location of provided public address using GeoIP2 module.")
    print("NOTE: Requires GeoLite2-Country.mmdb file installed in path. Only works on PUBLIC IP addresses.\n")
    geo_option = input("Print 1 to continue, 0 to go back: ")
    if geo_option == '1':
        try:
            dirname = os.path.dirname(__file__)
            db_path = os.path.join(dirname, "GeoLite2-Country.mmdb")
            reader = geoip2.database.Reader(db_path)
        except Exception as e:
            clear_screen()
            banner()
            print("GeoLite2-Country.mmdb file not found or error loading database.")
            print(f"Error: {e}")
            pause_screen()
            clear_screen()
            GeoLoc(data_file)
            return
        geoloc_input = input("Enter Public IP Address to locate: ")
        try:
            response = reader.country(geoloc_input)
            print(f"Country: {response.country.name}")
            pause_screen()
            clear_screen()
            menu2(data_file)
        except geoip2.errors.AddressNotFoundError:
            clear_screen()
            banner()
            print("Address not in database")
            pause_screen()
            clear_screen()
            GeoLoc(data_file)
        except ValueError:
            clear_screen()
            banner()
            print("Invalid Input")
            pause_screen()
            clear_screen()
            GeoLoc(data_file)
        except OSError:
            clear_screen()
            banner()
            print("Invalid Input")
            pause_screen()
            clear_screen()
            GeoLoc(data_file)
        except TypeError:
            clear_screen()
            banner()
            print("Invalid Input. Please provide an input")
            pause_screen()
            clear_screen()
            GeoLoc(data_file)
    elif geo_option == '0':
        clear_screen()
        menu2(data_file)
    else:
        clear_screen()
        banner()
        print("Invalid input given, please try again.")
        pause_screen()
        clear_screen()
        GeoLoc(data_file)

def about():
    clear_screen()
    banner()
    print("**Network Analyzer Program**")
    print("Network Analyzer analyzes the network information available in CSV format, captured using Wireshark or any other network/packet sniffing/capturing tool.")
    print("This is developed for cross-platform use.")
    print("Created By: Priyanshu Singh")
    print("GitHub: https://github.com/TheUnderdog553")
    print("LinkedIn: www.linkedin.com/in/priyanshu-singh-a50a22265")
    pause_screen()
    clear_screen()
    start_screen()

def exit_app():
    clear_screen()
    banner()
    exit_option = input("Are You Sure?(Y/N): ")
    if exit_option.lower() == 'y':
        clear_screen()
        print("Thank you for using Network Analyzer!")
        sys.exit(0)
    elif exit_option.lower() == 'n':
        clear_screen()
        start_screen()
    else:
        exit_app()

def start_screen():
    while True:
        clear_screen()
        banner()
        print("\n\t\t** MENU **\n")
        print("1. Start")
        print("2. About")
        print("3. Exit")
        try:
            menu_input = int(input("Enter your choice (1/2/3): "))
        except ValueError:
            clear_screen()
            banner()
            print("\n\nPlease enter an input.")
            pause_screen()
            clear_screen()
            continue
        if menu_input == 1:
            clear_screen()
            print("Let's start with Network Analysis:\n\n")
            try:
                file_path = input("Enter complete csv file path with readings: ")
                data_file = pd.read_csv(file_path)
                clear_screen()
                print("Data loaded successfully!\n\n")
                menu2(data_file)
            except FileNotFoundError:
                clear_screen()
                banner()
                print("\n\nERROR: FILE NOT FOUND. Enter valid file path.")
                pause_screen()
                clear_screen()
            except PermissionError:
                clear_screen()
                banner()
                print("\n\nPermission Error: Admin privileges required to run this command. Please try again.")
                pause_screen()
                clear_screen()
            except OSError:
                clear_screen()
                banner()
                print("\n\nERROR: Invalid argument. Please enter without quote marks.")
                pause_screen()
                clear_screen()
            except Exception as e:
                clear_screen()
                banner()
                print(f"\n\nERROR: {e}")
                pause_screen()
                clear_screen()
        elif menu_input == 2:
            about()
        elif menu_input == 3:
            exit_app()
            break
        else:
            clear_screen()
            banner()
            print("\n\nInvalid Input.")
            pause_screen()
            clear_screen()
            start_screen()

def check_dependencies():
    """Check if all required dependencies are installed"""
    missing_deps = []
    
    try:
        import pandas
    except ImportError:
        missing_deps.append("pandas")
    
    try:
        import matplotlib
    except ImportError:
        missing_deps.append("matplotlib")
    
    try:
        import networkx
    except ImportError:
        missing_deps.append("networkx")
    
    try:
        import geoip2
    except ImportError:
        missing_deps.append("geoip2")
    
    try:
        import pyfiglet
    except ImportError:
        missing_deps.append("pyfiglet")
    
    try:
        import pyvis
    except ImportError:
        missing_deps.append("pyvis")
    
    if missing_deps:
        print("Missing dependencies:")
        for dep in missing_deps:
            print(f"  - {dep}")
        print("\nPlease install missing dependencies using:")
        print(f"pip install {' '.join(missing_deps)}")
        return False
    
    return True

if __name__ == "__main__":
    # Check dependencies first
    if not check_dependencies():
        sys.exit(1)
    
    # Start the application
    start_screen()
