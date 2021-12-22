package com.aniks.springsecurity.student;

import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentMgtController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "Chukwusimdi Okose"),
            new Student(2, "Ekene Ugwu"),
            new Student(3, "Angelus Achi"),
            new Student(4, "Fabio Nwagbo"),
            new Student(5, "Kayode Akindele")
    );

    @GetMapping
    public List<Student> getAllStudents() {
        return STUDENTS;
    }

    @PostMapping
    public void registerStudent(@RequestBody Student student) {
        System.out.println("Register request: " + student);
    }

    @PutMapping(path = "{id}")
    public void updateStudent(@PathVariable(value = "id") Integer id, Student student) {
        System.out.println(String.format("%s %s", id, student));
    }

    @DeleteMapping(path = "{id}")
    public void deleteStudent(@PathVariable(value = "id") Integer id) {
        System.out.println("Deleting student: " + id);
    }
}
