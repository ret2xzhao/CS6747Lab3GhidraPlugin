import os

def generate_submission_dot_file():
    """
    Generates a submission.dot file on the Desktop directory.
    """
    example = """
    digraph "0x401000" {
        n1 [label = "0x401000; D: [esp], esp U: esi, esp"];
        n2 [label = "0x401001; D: esi U: ecx"];
        n3 [label = "0x401003; D: U: "];
        n4 [label = "0x401008; D: eflags U: [esp + 0x8], esp"];
        n5 [label = "0x40100d; D: U: eflags"];
        n6 [label = "0x40100f; D: [esp], esp U: esi, esp"];
        n7 [label = "0x401010; D: U: "];
        n8 [label = "0x401015; D: ecx, esp U: [esp], esp"];
        n9 [label = "0x401016; D: eax U: esi"];
        n10 [label = "0x401018; D: esi, esp U: [esp], esp"];
        n11 [label = "0x401019; D: esp U: [esp], esp"];
        n1 -> n2;
        n2 -> n3;
        n3 -> n4;
        n4 -> n5;
        n5 -> n9;
        n5 -> n6;
        n6 -> n7;
        n7 -> n8;
        n8 -> n9;
        n9 -> n10;
        n10 -> n11;
    }
    """

    # Define the file path to the Desktop directory
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    file_path = os.path.join(desktop_path, "submission.dot")

    # Write content to the file
    with open(file_path, "w") as file:
        file.write(example)
    print("submission.dot created.")


def main():
    generate_submission_dot_file()


if __name__ == '__main__':
    main()
