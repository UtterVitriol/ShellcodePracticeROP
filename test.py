class MyClass:
    x = 1

    def __init__(self, i):
        MyClass.x += i


def main():
    lel = MyClass(1)
    print(lel.x)

if __name__ == "__main__":
    main()